/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::calcard::{build_scheduling_paths, build_scheduling_resources, push_scheduling},
    calendar::{
        CALENDAR_SUBSCRIBED, Calendar, CalendarEvent, CalendarEventNotification,
        CalendarPreferences,
    },
    contact::{AddressBook, AddressBookPreferences, ContactCard},
    file::FileNode,
};
use ahash::AHashSet;
use calcard::{
    build_calcard_paths, build_calcard_resources, push_addressbook, push_calendar, push_card,
    push_event,
};
use common::{
    DAV_CHUNK, DavResourceRef, DavResources, ResourceStore, Server, UpdateLock,
    auth::AccountCache,
    cache::{
        LockResult,
        swap::{SwapKey, SwapPart},
    },
    storage::dav::ResourceChunkBuilder,
};
use file::{build_file_resources, build_nested_hierarchy, push_file};
use std::{sync::Arc, time::Instant};
use store::{
    ValueKey,
    ahash::AHashMap,
    query::log::{Change, Query},
    write::{Archive, ArchiveBytes, BatchBuilder, PendingId, ValueClass},
};
use trc::{AddContext, StoreEvent};
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};
use utils::cache::Cache;

pub mod calcard;
pub mod file;

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
            self.builders
                .push(ResourceChunkBuilder::with_capacity(DAV_CHUNK.min(64)));
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
    fn fetch_dav_resources(
        &self,
        access_account_id: u32,
        account_id: u32,
        collection: SyncCollection,
    ) -> impl Future<Output = trc::Result<Arc<DavResources>>> + Send;

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
        access_account_id: u32,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn cached_dav_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<DavResources>>;
}

impl GroupwareCache for Server {
    async fn fetch_dav_resources(
        &self,
        access_account_id: u32,
        account_id: u32,
        collection: SyncCollection,
    ) -> trc::Result<Arc<DavResources>> {
        let cache_store = match collection {
            SyncCollection::Calendar => &self.inner.cache.events,
            SyncCollection::AddressBook => &self.inner.cache.contacts,
            SyncCollection::FileNode => &self.inner.cache.files,
            SyncCollection::CalendarEventNotification => &self.inner.cache.scheduling,
            _ => unreachable!(),
        };
        let mut cache = match cache_store.get_value_or_guard_async(&account_id).await {
            Ok(cache) => cache,
            Err(guard) => {
                let start_time = Instant::now();
                match restore_cache_build(self, account_id, collection).await {
                    Some(cache) => {
                        if guard.insert(cache.clone()).is_err() {
                            cache_store.update(account_id, cache.clone());
                        }
                        warn_if_uncacheable(cache_store, account_id, collection, &cache);
                        cache
                    }
                    None => {
                        let cache = full_cache_build(
                            self,
                            account_id,
                            collection,
                            Arc::new(UpdateLock::new()),
                            access_account_id,
                        )
                        .await?;

                        if guard.insert(cache.clone()).is_err() {
                            cache_store.update(account_id, cache.clone());
                        }
                        warn_if_uncacheable(cache_store, account_id, collection, &cache);
                        self.inner.cache.swap.notify_changed(
                            account_id,
                            collection,
                            cache.resources.len() as u32,
                        );

                        trc::event!(
                            Store(StoreEvent::CacheMiss),
                            AccountId = account_id,
                            Collection = collection.as_str(),
                            Total = cache.resources.len(),
                            ChangeId = cache.highest_change_id,
                            Elapsed = start_time.elapsed(),
                        );

                        return Ok(cache);
                    }
                }
            }
        };

        // Obtain current state
        let start_time = Instant::now();
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
        if changes.is_truncated {
            let cache = full_cache_build(
                self,
                account_id,
                collection,
                cache.update_lock.clone(),
                access_account_id,
            )
            .await?;
            cache_store.update(account_id, cache.clone());
            warn_if_uncacheable(cache_store, account_id, collection, &cache);
            self.inner.cache.swap.notify_changed(
                account_id,
                collection,
                cache.resources.len() as u32,
            );

            trc::event!(
                Store(StoreEvent::CacheStale),
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
            trc::event!(
                Store(StoreEvent::CacheHit),
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
                cache = cache_store.peek(&account_id).unwrap_or(cache.clone());
                if cache.highest_change_id >= changes.to_change_id {
                    trc::event!(
                        Store(StoreEvent::CacheHit),
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
        let cache = if !matches!(collection, SyncCollection::CalendarEventNotification) {
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
            let mut rebuild_hierarchy = false;
            for ((is_container, document_id), slot) in &updated_resources {
                match slot {
                    Some(slot) => {
                        let updated = DavResourceRef {
                            chunk: &staging,
                            resource: &staging.records[*slot as usize],
                        };
                        match cache.resources.find(*document_id, *is_container) {
                            Some(previous) => {
                                rebuild_hierarchy =
                                    rebuild_hierarchy || updated.has_hierarchy_changes(&previous);
                            }
                            None => rebuild_hierarchy = true,
                        }
                    }
                    None => rebuild_hierarchy = true,
                }
            }

            let resources = cache.resources.rebuild(&staging, &updated_resources);
            let paths = if rebuild_hierarchy {
                Arc::new(if matches!(collection, SyncCollection::FileNode) {
                    build_nested_hierarchy(&resources)
                } else {
                    build_calcard_paths(&resources)
                })
            } else {
                cache.paths.clone()
            };

            let mut cache = DavResources {
                base_path: cache.base_path.clone(),
                paths,
                resources,
                item_change_id: changes.item_change_id.unwrap_or(cache.item_change_id),
                container_change_id: changes
                    .container_change_id
                    .unwrap_or(cache.container_change_id),
                highest_change_id: changes.to_change_id,
                size: 0,
                update_lock: lock.clone(),
            };
            cache.recompute_size();
            cache
        } else {
            let mut delete_ids = AHashSet::with_capacity(changes.changes.len());
            let mut inserted = Vec::new();

            for change in changes.changes {
                match change {
                    Change::InsertItem(document_id) => {
                        let document_id = document_id as u32;
                        if let Some(archive) = self
                            .store()
                            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                                account_id,
                                Collection::CalendarEventNotification,
                                document_id,
                            ))
                            .await
                            .caused_by(trc::location!())?
                        {
                            inserted.push((document_id, archive));
                        }
                    }
                    Change::DeleteItem(document_id) => {
                        delete_ids.insert(document_id as u32);
                    }
                    _ => {}
                }
            }
            inserted.sort_unstable_by_key(|(document_id, _)| *document_id);

            let mut containers = ChunkAccumulator::default();
            let mut items = ChunkAccumulator::default();
            let mut inserted = inserted.into_iter().peekable();

            for resource in cache.resources.iter() {
                if resource.is_container() {
                    containers.current().push_from(&resource);
                    continue;
                }
                if delete_ids.contains(&resource.document_id()) {
                    continue;
                }
                while inserted
                    .peek()
                    .is_some_and(|(document_id, _)| *document_id < resource.document_id())
                {
                    let (document_id, archive) = inserted.next().unwrap();
                    push_scheduling(
                        items.current(),
                        archive
                            .unarchive::<CalendarEventNotification>()
                            .caused_by(trc::location!())?,
                        document_id,
                    );
                }
                items.current().push_from(&resource);
            }
            for (document_id, archive) in inserted {
                push_scheduling(
                    items.current(),
                    archive
                        .unarchive::<CalendarEventNotification>()
                        .caused_by(trc::location!())?,
                    document_id,
                );
            }

            let resources = ResourceStore::from_sorted(containers.finish(), items.finish(), false);
            let paths = build_scheduling_paths(&resources);
            let mut cache = DavResources {
                base_path: cache.base_path.clone(),
                paths: Arc::new(paths),
                resources,
                item_change_id: changes.item_change_id.unwrap_or(cache.item_change_id),
                container_change_id: changes
                    .container_change_id
                    .unwrap_or(cache.container_change_id),
                highest_change_id: changes.to_change_id,
                size: 0,
                update_lock: cache.update_lock.clone(),
            };
            cache.recompute_size();
            cache
        };

        cache.update_lock.set_revision(cache.highest_change_id);
        let cache = Arc::new(cache);
        cache_store.update(account_id, cache.clone());
        warn_if_uncacheable(cache_store, account_id, collection, &cache);
        self.inner
            .cache
            .swap
            .notify_changed(account_id, collection, num_changes as u32);

        trc::event!(
            Store(StoreEvent::CacheUpdate),
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
                account_info_access.account_tenant_ids(),
                account_id,
                document_id,
                &mut batch,
            )?;

            batch
                .with_collection(Collection::Principal)
                .with_document(0)
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
                account_info_access.account_tenant_ids(),
                account_id,
                document_id,
                &mut batch,
            )?;

            // Set default calendar
            batch
                .with_collection(Collection::Principal)
                .with_document(0)
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

    async fn get_or_create_default_calendar(
        &self,
        access_account_id: u32,
        account_id: u32,
    ) -> trc::Result<Option<u32>> {
        let default_calendar_id = self
            .store()
            .get_value::<u32>(ValueKey {
                account_id,
                collection: Collection::Principal.into(),
                document_id: 0,
                class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
            })
            .await
            .caused_by(trc::location!())?;
        if default_calendar_id.is_some() {
            Ok(default_calendar_id)
        } else {
            self.fetch_dav_resources(access_account_id, account_id, SyncCollection::Calendar)
                .await
                .map(|c| c.document_ids(true).next())
        }
    }

    #[inline(always)]
    fn cached_dav_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<DavResources>> {
        (match collection {
            SyncCollection::Calendar => &self.inner.cache.events,
            SyncCollection::AddressBook => &self.inner.cache.contacts,
            SyncCollection::FileNode => &self.inner.cache.files,
            _ => unreachable!(),
        })
        .get(&account_id)
    }
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
    for change in changes {
        match change {
            Change::InsertItem(id) | Change::UpdateItem(id) => {
                let document_id = id as u32;
                if let Some(archive) = server
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                        account_id,
                        collection.collection(false),
                        document_id,
                    ))
                    .await
                    .caused_by(trc::location!())?
                {
                    let slot = staging.len() as u32;
                    push_from_archive(staging, archive, document_id, collection, false)?;
                    updated_resources.insert((has_no_children, document_id), Some(slot));
                } else {
                    updated_resources.insert((has_no_children, document_id), None);
                }
            }
            Change::DeleteItem(id) => {
                updated_resources.insert((has_no_children, id as u32), None);
            }
            Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                let document_id = id as u32;
                if let Some(archive) = server
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                        account_id,
                        collection.collection(true),
                        document_id,
                    ))
                    .await
                    .caused_by(trc::location!())?
                {
                    updated_resources.insert(
                        (true, document_id),
                        Some({
                            let slot = staging.len() as u32;
                            push_from_archive(staging, archive, document_id, collection, true)?;
                            slot
                        }),
                    );
                } else {
                    updated_resources.insert((true, document_id), None);
                }
            }
            Change::DeleteContainer(id) => {
                updated_resources.insert((true, id as u32), None);
            }
            Change::UpdateContainerProperty(_) => (),
        }
    }
    Ok(())
}

#[inline(always)]
fn warn_if_uncacheable(
    cache_store: &Cache<u32, Arc<DavResources>>,
    account_id: u32,
    collection: SyncCollection,
    cache: &Arc<DavResources>,
) {
    let capacity = cache_store.weight_capacity();
    if cache.size > capacity {
        trc::event!(
            Store(StoreEvent::CacheEntryTooLarge),
            AccountId = account_id,
            Collection = collection.as_str(),
            Size = cache.size,
            Limit = capacity,
        );
    }
}

async fn restore_cache_build(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
) -> Option<Arc<DavResources>> {
    if !server.inner.cache.swap.is_enabled() {
        return None;
    }

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

    let restored = DavResources::from_snapshot(&snapshot).or_else(|| {
        trc::event!(
            Store(StoreEvent::SwapMiss),
            AccountId = account_id,
            Collection = collection.as_str(),
            Details = "Discarded an unreadable resource cache snapshot",
        );
        None
    })?;

    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, collection.into())
        .await
        .caused_by(trc::location!())
        .inspect_err(|err| {
            trc::error!(err.clone());
        })
        .ok()?
        .unwrap_or_default();

    if restored.highest_change_id > last_change_id {
        trc::event!(
            Store(StoreEvent::SwapMiss),
            AccountId = account_id,
            Collection = collection.as_str(),
            ChangeId = restored.highest_change_id,
            Details = "Discarded a resource cache snapshot newer than the change log",
        );
        return None;
    }

    trc::event!(
        Store(StoreEvent::SwapHit),
        AccountId = account_id,
        Collection = collection.as_str(),
        ChangeId = restored.highest_change_id,
        Total = restored.resources.len(),
        Size = snapshot.len(),
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
) -> trc::Result<Arc<DavResources>> {
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
    .map(Arc::new)
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
            etag,
        ),
        _ => unreachable!(),
    }
    Ok(())
}
