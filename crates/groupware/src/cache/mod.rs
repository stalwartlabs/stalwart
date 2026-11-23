/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavResourceName, RFC_3986,
    cache::calcard::{build_scheduling_paths, build_scheduling_resources, push_scheduling},
    calendar::{
        CALENDAR_SUBSCRIBED, Calendar, CalendarEvent, CalendarEventNotification,
        CalendarPreferences,
    },
    contact::{AddressBook, AddressBookPreferences, ContactCard},
    file::FileNode,
};
use calcard::{
    build_calcard_paths, build_calcard_resources, push_addressbook, push_calendar, push_card,
    push_event,
};
use common::{
    DAV_CHUNK, GroupwareResources, ResourceChunk, Server, UpdateLock, Verification,
    auth::AccountCache,
    cache::{
        LockResult,
        swap::{
            BLOCKING_CODEC_THRESHOLD, SwapKey, SwapPart,
            writer::{SwapChanges, SwapTarget},
        },
    },
    storage::{
        batch::MAX_BATCH_DOCUMENTS,
        dav::{ResourceChunkBuilder, hierarchy::PathUpdate},
    },
};
use file::{build_file_resources, build_nested_hierarchy, push_file};
use registry::schema::enums::StorageQuota;
use std::{collections::hash_map::Entry, sync::Arc, time::Instant};
use store::{
    IterateParams, U32_LEN, ValueKey,
    ahash::AHashMap,
    query::log::{Change, Query},
    write::{
        Archive, ArchiveBytes, BatchBuilder, PendingId, ValueClass, assert::AssertValue,
        key::DeserializeBigEndian,
    },
};
use trc::{AddContext, CacheEvent};
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

pub mod calcard;
pub mod file;

impl DavResourceName {
    pub fn account_base_path(&self, account_name: &str) -> String {
        format!(
            "{}/{}/",
            self.base_path(),
            percent_encoding::utf8_percent_encode(account_name, RFC_3986)
        )
    }
}

#[derive(Default)]
pub struct ChunkAccumulator {
    builders: Vec<ResourceChunkBuilder>,
}

impl ChunkAccumulator {
    pub fn current(&mut self) -> &mut ResourceChunkBuilder {
        if self
            .builders
            .last()
            .is_none_or(|builder| builder.len() >= DAV_CHUNK)
        {
            self.builders.push(ResourceChunkBuilder::with_capacity(64));
        }
        self.builders.last_mut().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.builders.iter().all(|builder| builder.is_empty())
    }

    pub fn len(&self) -> usize {
        self.builders.iter().map(|builder| builder.len()).sum()
    }

    pub fn finish(self) -> Vec<ResourceChunkBuilder> {
        self.builders
            .into_iter()
            .filter(|builder| !builder.is_empty())
            .collect()
    }
}

pub trait GroupwareCache: Sync + Send {
    fn fetch_groupware_resources(
        &self,
        access_account_id: u32,
        account_id: u32,
        collection: SyncCollection,
    ) -> impl Future<Output = trc::Result<Arc<GroupwareResources>>> + Send;

    fn fetch_groupware_resources_at(
        &self,
        access_account_id: u32,
        account_id: u32,
        collection: SyncCollection,
        min_change_id: u64,
    ) -> impl Future<Output = trc::Result<Arc<GroupwareResources>>> + Send;

    fn create_default_addressbook(
        &self,
        account_info_access: &AccountCache,
        account_info_owner: &AccountCache,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn create_default_calendar(
        &self,
        account_info_access: &AccountCache,
        account_info_owner: &AccountCache,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn get_or_create_default_calendar(
        &self,
        account_info_access: &AccountCache,
        account_info_owner: &AccountCache,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn default_calendar_id(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn cached_groupware_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<GroupwareResources>>;

    fn count_documents(
        &self,
        account_id: u32,
        collection: Collection,
        limit: usize,
    ) -> impl Future<Output = trc::Result<usize>> + Send;
}

impl GroupwareCache for Server {
    fn fetch_groupware_resources(
        &self,
        access_account_id: u32,
        account_id: u32,
        collection: SyncCollection,
    ) -> impl Future<Output = trc::Result<Arc<GroupwareResources>>> + Send {
        self.fetch_groupware_resources_at(access_account_id, account_id, collection, 0)
    }

    async fn fetch_groupware_resources_at(
        &self,
        access_account_id: u32,
        account_id: u32,
        collection: SyncCollection,
        min_change_id: u64,
    ) -> trc::Result<Arc<GroupwareResources>> {
        let caches = &self.inner.cache;
        let mut cache = match caches.resident_resources(account_id, collection) {
            Some(cache) => cache,
            None => match load_cache(self, account_id, collection, access_account_id).await? {
                LoadedCache::Resident(cache) => cache,
                LoadedCache::Built(cache) => return Ok(cache),
            },
        };

        // Serve the snapshot without revalidating while it is within the freshness window
        let start_time = Instant::now();
        let revalidate = &self.inner.cache.revalidate;
        if cache.is_fresh(revalidate) && cache.highest_change_id >= min_change_id {
            trc::event!(
                Cache(CacheEvent::Hit),
                AccountId = account_id,
                Collection = collection.as_str(),
                ChangeId = cache.highest_change_id,
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Obtain current state
        let verification = Verification::capture(revalidate, &cache.update_lock);
        let changes = self
            .core
            .storage
            .data
            .changes(
                account_id,
                collection.into(),
                Query::Since(cache.highest_change_id),
            )
            .await
            .caused_by(trc::location!())?;

        // Regenerate cache if the change log has been truncated
        if changes.needs_full_rebuild(cache.highest_change_id) {
            let cache = full_cache_build(
                self,
                account_id,
                collection,
                cache.update_lock.clone(),
                access_account_id,
                verification,
            )
            .await?;
            caches.publish_resources(
                account_id,
                collection,
                &cache,
                Some(SwapChanges::rebuilt(
                    cache.highest_change_id,
                    cache.resources.len(),
                )),
            );

            trc::event!(
                Cache(CacheEvent::Stale),
                AccountId = account_id,
                Collection = collection.as_str(),
                ChangeId = cache.highest_change_id,
                Total = cache.resources.len(),
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Verify changes
        if changes.changes.is_empty() {
            let cache = if verification.is_current(&cache.update_lock) {
                let mut verified = cache.as_ref().clone();
                verified.verification = verification;
                let verified = Arc::new(verified);
                caches.publish_resources(account_id, collection, &verified, None);
                verified
            } else {
                cache
            };

            trc::event!(
                Cache(CacheEvent::Hit),
                AccountId = account_id,
                Collection = collection.as_str(),
                ChangeId = cache.highest_change_id,
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Lock for updates
        let lock = cache.update_lock.clone();
        let _permit = match lock.acquire(cache.highest_change_id).await? {
            LockResult::Acquired(permit) => permit,
            LockResult::Stale(permit) => {
                cache = caches
                    .peek_resources(account_id, collection)
                    .unwrap_or(cache);
                if cache.highest_change_id >= changes.to_change_id {
                    trc::event!(
                        Cache(CacheEvent::Hit),
                        AccountId = account_id,
                        Collection = collection.as_str(),
                        ChangeId = cache.highest_change_id,
                        Elapsed = start_time.elapsed(),
                    );
                    return Ok(cache);
                }

                permit
            }
        };

        let num_changes = changes.changes.len();
        let base_change_id = cache.highest_change_id;
        let mut updated_resources = AHashMap::with_capacity(8);
        let has_no_children = collection == SyncCollection::FileNode;
        let mut staging = ResourceChunkBuilder::with_capacity(8);

        process_changes(
            self,
            account_id,
            collection,
            has_no_children,
            &mut staging,
            &mut updated_resources,
            changes.changes,
        )
        .await?;

        let staging = staging.finish();
        let mut cache = rebuild_cache(&cache, collection, &staging, &updated_resources);
        cache.item_change_id = changes.item_change_id.unwrap_or(cache.item_change_id);
        cache.container_change_id = changes
            .container_change_id
            .unwrap_or(cache.container_change_id);
        cache.highest_change_id = changes.to_change_id;
        cache.update_lock = lock.clone();
        cache.verification = verification;

        cache.update_lock.set_revision(cache.highest_change_id);
        let cache = Arc::new(cache);
        let swap_changes = SwapChanges::applied(
            num_changes,
            base_change_id,
            cache.highest_change_id,
            cache.resources.len(),
        );
        caches.publish_resources(account_id, collection, &cache, Some(swap_changes));

        trc::event!(
            Cache(CacheEvent::Update),
            AccountId = account_id,
            Collection = collection.as_str(),
            ChangeId = cache.highest_change_id,
            Details = num_changes,
            Total = cache.resources.len(),
            Elapsed = start_time.elapsed(),
        );

        Ok(cache)
    }

    async fn create_default_addressbook(
        &self,
        account_info_access: &AccountCache,
        account_info_owner: &AccountCache,
    ) -> trc::Result<Option<u32>> {
        if let Some(name) = &self.core.groupware.default_addressbook_name {
            let mut batch = BatchBuilder::new();
            let account_id = account_info_owner.account_id();
            let account_name = account_info_owner.name();
            let document_id = batch.reserve_document_id(account_id, Collection::AddressBook);
            AddressBook {
                name: name.clone(),
                preferences: vec![AddressBookPreferences {
                    account_id,
                    name: format!(
                        "{} ({})",
                        self.core
                            .groupware
                            .default_addressbook_display_name
                            .as_ref()
                            .unwrap_or(name),
                        account_name
                    ),
                    ..Default::default()
                }],
                subscribers: vec![account_id],
                ..Default::default()
            }
            .insert(
                account_info_access.changed_by(),
                account_id,
                document_id,
                &mut batch,
            )?;

            batch
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(PrincipalField::DefaultAddressBookId, AssertValue::None)
                .set(
                    PrincipalField::DefaultAddressBookId,
                    PendingId::Slot(document_id),
                );

            let ids = self.commit_batch(batch).await?;
            Ok(Some(ids.slot(document_id)))
        } else {
            Ok(None)
        }
    }

    async fn create_default_calendar(
        &self,
        account_info_access: &AccountCache,
        account_info_owner: &AccountCache,
    ) -> trc::Result<Option<u32>> {
        if let Some(name) = &self.core.groupware.default_calendar_name {
            let mut batch = BatchBuilder::new();
            let account_id = account_info_owner.account_id();
            let account_name = account_info_owner.name();
            let document_id = batch.reserve_document_id(account_id, Collection::Calendar);
            Calendar {
                name: name.clone(),
                preferences: vec![CalendarPreferences {
                    account_id,
                    name: format!(
                        "{} ({})",
                        self.core
                            .groupware
                            .default_calendar_display_name
                            .as_ref()
                            .unwrap_or(name),
                        account_name
                    ),
                    flags: CALENDAR_SUBSCRIBED,
                    ..Default::default()
                }],
                ..Default::default()
            }
            .insert(
                account_info_access.changed_by(),
                account_id,
                document_id,
                &mut batch,
            )?;

            // Set default calendar
            batch
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(PrincipalField::DefaultCalendarId, AssertValue::None)
                .set(
                    PrincipalField::DefaultCalendarId,
                    PendingId::Slot(document_id),
                );

            let ids = self.commit_batch(batch).await?;
            Ok(Some(ids.slot(document_id)))
        } else {
            Ok(None)
        }
    }

    async fn default_calendar_id(&self, account_id: u32) -> trc::Result<Option<u32>> {
        any_calendar_id(self, account_id).await
    }

    async fn get_or_create_default_calendar(
        &self,
        account_info_access: &AccountCache,
        account_info_owner: &AccountCache,
    ) -> trc::Result<Option<u32>> {
        let account_id = account_info_owner.account_id();
        if let Some(calendar_id) = any_calendar_id(self, account_id).await? {
            return Ok(Some(calendar_id));
        }

        match self
            .create_default_calendar(account_info_access, account_info_owner)
            .await
        {
            Err(err) if err.is_assertion_failure() => any_calendar_id(self, account_id).await,
            result => result,
        }
    }

    async fn count_documents(
        &self,
        account_id: u32,
        collection: Collection,
        limit: usize,
    ) -> trc::Result<usize> {
        let caches = &self.inner.cache;
        let counted = match collection {
            Collection::CalendarEvent => {
                Some((SyncCollection::Calendar, StorageQuota::MaxCalendarEvents))
            }
            Collection::CalendarEventNotification => Some((
                SyncCollection::CalendarEventNotification,
                StorageQuota::MaxCalendarEventNotifications,
            )),
            _ => None,
        };
        if let Some((collection, object)) = counted {
            return match caches
                .peek_resources(account_id, collection)
                .filter(|resources| resources.is_fresh(&caches.revalidate))
            {
                Some(resources) => Ok(resources.resources.count(false)),
                None => self
                    .object_count(account_id, object)
                    .await
                    .caused_by(trc::location!()),
            };
        }

        let cached = match collection {
            Collection::Calendar => Some(SyncCollection::Calendar),
            Collection::AddressBook | Collection::ContactCard => Some(SyncCollection::AddressBook),
            _ => None,
        }
        .filter(|collection| caches.has_resources(account_id, *collection));
        if let Some(sync_collection) = cached {
            let is_container = matches!(collection, Collection::Calendar | Collection::AddressBook);
            return self
                .fetch_groupware_resources(account_id, account_id, sync_collection)
                .await
                .map(|resources| resources.resources.count(is_container));
        }

        let mut count = 0;
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey::archive(account_id, collection, 0),
                    ValueKey::archive(account_id, collection, u32::MAX),
                )
                .no_values()
                .limit(limit),
                |_, _| {
                    count += 1;
                    Ok(count < limit)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| count)
    }

    #[inline(always)]
    fn cached_groupware_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<GroupwareResources>> {
        self.inner.cache.resident_resources(account_id, collection)
    }
}

async fn any_calendar_id(server: &Server, account_id: u32) -> trc::Result<Option<u32>> {
    if let Some(calendar_id) = server
        .store()
        .get_value::<u32>(ValueKey {
            account_id,
            collection: Collection::Principal.into(),
            document_id: 0,
            class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
        })
        .await
        .caused_by(trc::location!())?
    {
        return Ok(Some(calendar_id));
    }

    let mut calendar_id = None;
    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::archive(account_id, Collection::Calendar, 0),
                ValueKey::archive(account_id, Collection::Calendar, u32::MAX),
            )
            .no_values()
            .ascending()
            .only_first(),
            |key, _| {
                calendar_id = key.deserialize_be_u32(key.len() - U32_LEN).map(Some)?;
                Ok(false)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| calendar_id)
}

fn rebuild_cache(
    previous: &GroupwareResources,
    collection: SyncCollection,
    staging: &ResourceChunk,
    changes: &AHashMap<(bool, u32), Option<u32>>,
) -> GroupwareResources {
    let mut updated = GroupwareResources {
        base_path: previous.base_path.clone(),
        paths: previous.paths.clone(),
        resources: previous.resources.rebuild(staging, changes),
        item_change_id: previous.item_change_id,
        container_change_id: previous.container_change_id,
        highest_change_id: previous.highest_change_id,
        size: 0,
        update_lock: previous.update_lock.clone(),
        verification: Default::default(),
    };

    match updated.patch_paths(&previous.resources, staging, changes) {
        PathUpdate::Shared => {}
        PathUpdate::Patched(paths) => updated.paths = Arc::new(paths),
        PathUpdate::Rebuild => {
            updated.paths = Arc::new(match collection {
                SyncCollection::FileNode => build_nested_hierarchy(&updated.resources),
                SyncCollection::CalendarEventNotification => {
                    build_scheduling_paths(&updated.resources)
                }
                _ => build_calcard_paths(&updated.resources),
            })
        }
    }

    updated.recompute_size();
    updated
}

async fn process_changes(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
    has_no_children: bool,
    staging: &mut ResourceChunkBuilder,
    updated_resources: &mut AHashMap<(bool, u32), Option<u32>>,
    changes: Vec<Change>,
) -> trc::Result<()> {
    let mut item_ids = Vec::new();
    for change in changes.into_iter().rev() {
        match change {
            Change::InsertItem(id) | Change::UpdateItem(id) | Change::UpdateItemMetadata(id) => {
                let document_id = id as u32;
                if let Entry::Vacant(entry) =
                    updated_resources.entry((has_no_children, document_id))
                {
                    entry.insert(None);
                    item_ids.push(document_id);
                }
            }
            Change::DeleteItem(id) => {
                updated_resources
                    .entry((has_no_children, id as u32))
                    .or_insert(None);
            }
            Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                fetch_container(
                    server,
                    account_id,
                    collection,
                    id as u32,
                    staging,
                    updated_resources,
                )
                .await?;
            }
            Change::UpdateContainerPartial(id, partial) if partial.has_metadata() => {
                fetch_container(
                    server,
                    account_id,
                    collection,
                    id as u32,
                    staging,
                    updated_resources,
                )
                .await?;
            }
            Change::DeleteContainer(id) => {
                updated_resources.entry((true, id as u32)).or_insert(None);
            }
            Change::UpdateContainerPartial(..) => (),
        }
    }

    item_ids.sort_unstable();
    for chunk in item_ids.chunks(MAX_BATCH_DOCUMENTS) {
        let mut archives = server
            .archive_chunk(account_id, collection.collection(false), chunk, None)
            .await
            .caused_by(trc::location!())?;
        for &document_id in chunk {
            if let Some(archive) = archives.take_archive(document_id) {
                let slot = staging.len() as u32;
                push_from_archive(staging, archive, document_id, collection, false)?;
                updated_resources.insert((has_no_children, document_id), Some(slot));
            }
        }
    }
    Ok(())
}

async fn fetch_container(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
    document_id: u32,
    staging: &mut ResourceChunkBuilder,
    updated_resources: &mut AHashMap<(bool, u32), Option<u32>>,
) -> trc::Result<()> {
    let Entry::Vacant(entry) = updated_resources.entry((true, document_id)) else {
        return Ok(());
    };
    let slot = if let Some(archive) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            collection.collection(true),
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
    {
        let slot = staging.len() as u32;
        push_from_archive(staging, archive, document_id, collection, true)?;
        Some(slot)
    } else {
        None
    };
    entry.insert(slot);
    Ok(())
}

enum LoadedCache {
    Resident(Arc<GroupwareResources>),
    Built(Arc<GroupwareResources>),
}

async fn load_cache(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
    access_account_id: u32,
) -> trc::Result<LoadedCache> {
    Box::pin(load_missing_cache(
        server,
        account_id,
        collection,
        access_account_id,
    ))
    .await
}

async fn load_missing_cache(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
    access_account_id: u32,
) -> trc::Result<LoadedCache> {
    let caches = &server.inner.cache;
    let Some(resources) = caches.resources(collection) else {
        return Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Unsupported groupware collection")
            .caused_by(trc::location!()));
    };
    let guard = match resources.get_value_or_guard_async(&account_id).await {
        Ok(cache) => return Ok(LoadedCache::Resident(cache)),
        Err(guard) => guard,
    };

    if let Some(cache) = caches
        .resources_large
        .lookup(SwapTarget::new(account_id, collection))
    {
        drop(guard);
        return Ok(LoadedCache::Resident(cache));
    }

    let start_time = Instant::now();
    if let Some(cache) = restore_cache_build(server, account_id, collection).await {
        caches.publish_loaded_resources(guard, account_id, collection, &cache, None);
        return Ok(LoadedCache::Resident(cache));
    }

    let cache = full_cache_build(
        server,
        account_id,
        collection,
        Arc::new(UpdateLock::new()),
        access_account_id,
        Default::default(),
    )
    .await?;
    caches.publish_loaded_resources(
        guard,
        account_id,
        collection,
        &cache,
        Some(SwapChanges::rebuilt(
            cache.highest_change_id,
            cache.resources.len(),
        )),
    );

    trc::event!(
        Cache(CacheEvent::Miss),
        AccountId = account_id,
        Collection = collection.as_str(),
        Total = cache.resources.len(),
        ChangeId = cache.highest_change_id,
        Elapsed = start_time.elapsed(),
    );

    Ok(LoadedCache::Built(cache))
}

async fn restore_cache_build(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
) -> Option<Arc<GroupwareResources>> {
    if !server.inner.cache.swap.is_enabled() {
        return None;
    }

    Box::pin(restore_swapped_cache(server, account_id, collection)).await
}

async fn restore_swapped_cache(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
) -> Option<Arc<GroupwareResources>> {
    let start_time = Instant::now();
    let key = SwapKey::new(account_id, collection, SwapPart::Resources);
    let snapshot = match server.inner.cache.swap.load(key).await {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return None,
        Err(err) => {
            trc::error!(
                err.details("Failed to read the resource cache snapshot")
                    .ctx(trc::Key::AccountId, account_id)
                    .ctx(trc::Key::Collection, collection.as_str())
            );
            return None;
        }
    };

    let snapshot_len = snapshot.len();
    let restored = if snapshot_len >= BLOCKING_CODEC_THRESHOLD {
        tokio::task::spawn_blocking(move || GroupwareResources::from_snapshot(&snapshot))
            .await
            .ok()
            .flatten()
    } else {
        GroupwareResources::from_snapshot(&snapshot)
    }
    .or_else(|| {
        trc::event!(
            Cache(CacheEvent::SwapMiss),
            AccountId = account_id,
            Collection = collection.as_str(),
            Details = "Discarded an unreadable resource cache snapshot",
        );
        None
    })?;

    let base_path = DavResourceName::from(collection)
        .account_base_path(server.account(account_id).await.ok()?.name());
    if restored.base_path != base_path {
        trc::event!(
            Cache(CacheEvent::SwapMiss),
            AccountId = account_id,
            Collection = collection.as_str(),
            Details = "Discarded a resource cache snapshot with a stale base path",
        );
        return None;
    }

    trc::event!(
        Cache(CacheEvent::SwapHit),
        AccountId = account_id,
        Collection = collection.as_str(),
        ChangeId = restored.highest_change_id,
        Total = restored.resources.len(),
        Size = snapshot_len,
        Elapsed = start_time.elapsed(),
    );

    Some(Arc::new(restored))
}

async fn full_cache_build(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
    update_lock: Arc<UpdateLock>,
    access_account_id: u32,
    verification: Verification,
) -> trc::Result<Arc<GroupwareResources>> {
    Box::pin(build_full_cache(
        server,
        account_id,
        collection,
        update_lock,
        access_account_id,
        verification,
    ))
    .await
}

async fn build_full_cache(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
    update_lock: Arc<UpdateLock>,
    access_account_id: u32,
    verification: Verification,
) -> trc::Result<Arc<GroupwareResources>> {
    match collection {
        SyncCollection::Calendar => {
            build_calcard_resources(
                server,
                access_account_id,
                account_id,
                SyncCollection::Calendar,
                Collection::Calendar,
                Collection::CalendarEvent,
                update_lock,
            )
            .await
        }
        SyncCollection::AddressBook => {
            build_calcard_resources(
                server,
                access_account_id,
                account_id,
                SyncCollection::AddressBook,
                Collection::AddressBook,
                Collection::ContactCard,
                update_lock,
            )
            .await
        }
        SyncCollection::FileNode => build_file_resources(server, account_id, update_lock).await,
        SyncCollection::CalendarEventNotification => {
            build_scheduling_resources(server, account_id, update_lock).await
        }
        _ => unreachable!(),
    }
    .map(|mut cache| {
        cache.verification = verification;
        Arc::new(cache)
    })
}

fn push_from_archive(
    builder: &mut ResourceChunkBuilder,
    archive: Archive<ArchiveBytes>,
    document_id: u32,
    collection: SyncCollection,
    is_container: bool,
) -> trc::Result<()> {
    let etag = archive.version.hash().unwrap_or_default();

    match collection {
        SyncCollection::Calendar => {
            if is_container {
                push_calendar(
                    builder,
                    archive
                        .unarchive::<Calendar>()
                        .caused_by(trc::location!())?,
                    document_id,
                    etag,
                );
            } else {
                push_event(
                    builder,
                    archive
                        .unarchive::<CalendarEvent>()
                        .caused_by(trc::location!())?,
                    document_id,
                );
            }
        }
        SyncCollection::AddressBook => {
            if is_container {
                push_addressbook(
                    builder,
                    archive
                        .unarchive::<AddressBook>()
                        .caused_by(trc::location!())?,
                    document_id,
                    etag,
                );
            } else {
                push_card(
                    builder,
                    archive
                        .unarchive::<ContactCard>()
                        .caused_by(trc::location!())?,
                    document_id,
                );
            }
        }
        SyncCollection::FileNode => push_file(
            builder,
            archive
                .unarchive::<FileNode>()
                .caused_by(trc::location!())?,
            document_id,
        ),
        SyncCollection::CalendarEventNotification => push_scheduling(
            builder,
            archive
                .unarchive::<CalendarEventNotification>()
                .caused_by(trc::location!())?,
            document_id,
        ),
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/groupware/src/cache/tests.rs"]
mod tests;
