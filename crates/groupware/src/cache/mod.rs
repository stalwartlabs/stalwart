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
        swap::{BLOCKING_CODEC_THRESHOLD, SwapKey, SwapPart},
    },
    storage::dav::{ResourceChunkBuilder, hierarchy::PathUpdate},
};
use file::{build_file_resources, build_nested_hierarchy, push_file};
use std::{sync::Arc, time::Instant};
use store::{
    ValueKey,
    ahash::AHashMap,
    query::log::{Change, Query},
    write::{Archive, ArchiveBytes, BatchBuilder, PendingId, ValueClass},
};
use trc::{AddContext, CacheEvent};
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};
use utils::cache::Cache;

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

    fn cached_groupware_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<GroupwareResources>>;
}

impl GroupwareCache for Server {
    async fn fetch_groupware_resources(
        &self,
        access_account_id: u32,
        account_id: u32,
        collection: SyncCollection,
    ) -> trc::Result<Arc<GroupwareResources>> {
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
                        if admit(cache_store, account_id, collection, &cache) {
                            let _ = guard.insert(cache.clone());
                        }
                        cache
                    }
                    None => {
                        let cache = full_cache_build(
                            self,
                            account_id,
                            collection,
                            Arc::new(UpdateLock::new()),
                            access_account_id,
                            Default::default(),
                        )
                        .await?;

                        if admit(cache_store, account_id, collection, &cache) {
                            let _ = guard.insert(cache.clone());
                            self.inner.cache.swap.notify_changed(
                                account_id,
                                collection,
                                cache.resources.len() as u32,
                            );
                        } else {
                            self.inner.cache.swap.notify_refresh_resources(
                                account_id,
                                collection,
                                cache.resources.len() as u32,
                                &cache,
                            );
                        }

                        trc::event!(
                            Cache(CacheEvent::Miss),
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

        // Serve the snapshot without revalidating while it is within the freshness window
        let start_time = Instant::now();
        let revalidate = &self.inner.cache.revalidate;
        if cache.is_fresh(revalidate) {
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
            if admit(cache_store, account_id, collection, &cache) {
                cache_store.update(account_id, cache.clone());
                self.inner.cache.swap.notify_changed(
                    account_id,
                    collection,
                    cache.resources.len() as u32,
                );
            } else {
                cache_store.remove(&account_id);
                self.inner.cache.swap.notify_refresh_resources(
                    account_id,
                    collection,
                    cache.resources.len() as u32,
                    &cache,
                );
            }

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
                cache_store.update(account_id, verified.clone());
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
                cache = cache_store.peek(&account_id).unwrap_or(cache.clone());
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
        if admit(cache_store, account_id, collection, &cache) {
            cache_store.update(account_id, cache.clone());
            self.inner
                .cache
                .swap
                .notify_changed(account_id, collection, num_changes as u32);
        } else {
            cache_store.remove(&account_id);
            self.inner.cache.swap.notify_refresh_resources(
                account_id,
                collection,
                num_changes as u32,
                &cache,
            );
        }

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
            self.fetch_groupware_resources(access_account_id, account_id, SyncCollection::Calendar)
                .await
                .map(|c| c.document_ids(true).next())
        }
    }

    #[inline(always)]
    fn cached_groupware_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<GroupwareResources>> {
        (match collection {
            SyncCollection::Calendar => &self.inner.cache.events,
            SyncCollection::AddressBook => &self.inner.cache.contacts,
            SyncCollection::FileNode => &self.inner.cache.files,
            _ => unreachable!(),
        })
        .get(&account_id)
    }
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
fn admit(
    cache_store: &Cache<u32, Arc<GroupwareResources>>,
    account_id: u32,
    collection: SyncCollection,
    cache: &Arc<GroupwareResources>,
) -> bool {
    if !cache_store.is_oversized(&account_id, cache) {
        return true;
    }

    trc::event!(
        Cache(CacheEvent::EntryTooLarge),
        AccountId = account_id,
        Collection = collection.as_str(),
        Size = cache.size,
        Limit = cache_store.admission_limit(),
    );
    false
}

async fn restore_cache_build(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
) -> Option<Arc<GroupwareResources>> {
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
            etag,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::{SCHEDULE_INBOX_ID, SCHEDULE_OUTBOX_ID};
    use common::{
        ArenaRef, DavName, GroupwareResource, GroupwareResourceMetadata, NO_ID, ResourceStore,
        storage::dav::CONTAINER_FLAG,
    };

    #[derive(Clone)]
    enum Spec {
        Container {
            document_id: u32,
            name: String,
        },
        Event {
            document_id: u32,
            names: Vec<(u32, String)>,
            etag: u32,
        },
        Node {
            document_id: u32,
            name: String,
            parent_id: Option<u32>,
            size: Option<u32>,
            etag: u32,
        },
        Notification {
            document_id: u32,
        },
    }

    fn calendar(document_id: u32, name: &str) -> Spec {
        Spec::Container {
            document_id,
            name: name.to_string(),
        }
    }

    fn event(document_id: u32, parent_id: u32, name: &str) -> Spec {
        Spec::Event {
            document_id,
            names: vec![(parent_id, name.to_string())],
            etag: 0,
        }
    }

    fn folder(document_id: u32, name: &str, parent_id: Option<u32>) -> Spec {
        Spec::Node {
            document_id,
            name: name.to_string(),
            parent_id,
            size: None,
            etag: 0,
        }
    }

    fn file(document_id: u32, name: &str, parent_id: Option<u32>) -> Spec {
        Spec::Node {
            document_id,
            name: name.to_string(),
            parent_id,
            size: Some(1024),
            etag: 0,
        }
    }

    impl Spec {
        fn document_id(&self) -> u32 {
            match self {
                Spec::Container { document_id, .. }
                | Spec::Event { document_id, .. }
                | Spec::Node { document_id, .. }
                | Spec::Notification { document_id } => *document_id,
            }
        }

        fn is_container(&self) -> bool {
            match self {
                Spec::Container { .. } => true,
                Spec::Node { size, .. } => size.is_none(),
                Spec::Event { .. } => false,
                Spec::Notification { document_id } => {
                    *document_id == SCHEDULE_INBOX_ID || *document_id == SCHEDULE_OUTBOX_ID
                }
            }
        }

        fn with_etag(mut self, value: u32) -> Self {
            match &mut self {
                Spec::Event { etag, .. } | Spec::Node { etag, .. } => *etag = value,
                _ => {}
            }
            self
        }

        fn push(&self, builder: &mut ResourceChunkBuilder) {
            match self {
                Spec::Container { document_id, name } => {
                    let name = builder.push_str(name);
                    let acls = builder.push_acls(&[]);
                    let preferences = builder.push_prefs(&[]);
                    builder.records.push(GroupwareResource {
                        document_id: *document_id,
                        data: GroupwareResourceMetadata::Calendar {
                            name,
                            acls,
                            preferences,
                            etag: 0,
                        },
                    });
                }
                Spec::Event {
                    document_id,
                    names,
                    etag,
                } => {
                    let names = builder.push_names(
                        &names
                            .iter()
                            .map(|(parent_id, name)| DavName::new(name.clone(), *parent_id))
                            .collect::<Vec<_>>(),
                    );
                    let uid = builder.push_str("uid");
                    builder.records.push(GroupwareResource {
                        document_id: *document_id,
                        data: GroupwareResourceMetadata::CalendarEvent {
                            names,
                            start: 0,
                            duration: 0,
                            created_at: 0,
                            modified_at: 0,
                            uid,
                            etag: *etag,
                        },
                    });
                }
                Spec::Node {
                    document_id,
                    name,
                    parent_id,
                    size,
                    etag,
                } => {
                    let name = builder.push_str(name);
                    let acls = builder.push_acls(&[]);
                    builder.records.push(GroupwareResource {
                        document_id: *document_id,
                        data: GroupwareResourceMetadata::File {
                            name,
                            size: size.unwrap_or(NO_ID),
                            parent_id: parent_id.unwrap_or(NO_ID),
                            acls,
                            etag: *etag,
                        },
                    });
                }
                Spec::Notification { document_id } => {
                    let names = if self.is_container() {
                        ArenaRef::default()
                    } else {
                        builder.push_names(&[DavName::new(
                            format!("{document_id}.ics"),
                            SCHEDULE_INBOX_ID,
                        )])
                    };
                    builder.records.push(GroupwareResource {
                        document_id: *document_id,
                        data: GroupwareResourceMetadata::CalendarEventNotification {
                            names,
                            created_at: 0,
                            event_id: u32::MAX,
                            etag: 0,
                        },
                    });
                }
            }
        }
    }

    fn cold_build(specs: &[Spec], collection: SyncCollection) -> GroupwareResources {
        let unified = collection == SyncCollection::FileNode;
        let mut containers = ChunkAccumulator::default();
        let mut items = ChunkAccumulator::default();

        let mut sorted = specs.to_vec();
        sorted.sort_by_key(|spec| (!unified && !spec.is_container(), spec.document_id()));
        for spec in &sorted {
            if unified || spec.is_container() {
                spec.push(containers.current());
            } else {
                spec.push(items.current());
            }
        }

        let resources = ResourceStore::from_sorted(containers.finish(), items.finish(), unified);
        let paths = match collection {
            SyncCollection::FileNode => build_nested_hierarchy(&resources),
            SyncCollection::CalendarEventNotification => build_scheduling_paths(&resources),
            _ => build_calcard_paths(&resources),
        };
        let mut cache = GroupwareResources {
            base_path: "/dav/x/john/".to_string(),
            paths: Arc::new(paths),
            resources,
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };
        cache.recompute_size();
        cache
    }

    fn apply(
        previous: &GroupwareResources,
        collection: SyncCollection,
        changes: &[(bool, u32, Option<Spec>)],
    ) -> GroupwareResources {
        let mut staging = ResourceChunkBuilder::with_capacity(changes.len());
        let mut map: AHashMap<(bool, u32), Option<u32>> = AHashMap::with_capacity(changes.len());

        for (is_container, document_id, spec) in changes {
            let slot = spec.as_ref().map(|spec| {
                let slot = staging.len() as u32;
                spec.push(&mut staging);
                slot
            });
            map.insert((*is_container, *document_id), slot);
        }

        rebuild_cache(previous, collection, &staging.finish(), &map)
    }

    fn entries(cache: &GroupwareResources) -> Vec<(String, u32, u32, u32)> {
        let mut entries = cache
            .paths
            .iter()
            .map(|(chunk, path)| {
                (
                    chunk.path_str(path).to_string(),
                    path.document_id,
                    path.parent_id,
                    path.hierarchy_seq,
                )
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    fn records(cache: &GroupwareResources) -> Vec<(u32, bool, Vec<String>, u32)> {
        cache
            .resources
            .iter()
            .map(|resource| {
                (
                    resource.document_id(),
                    resource.is_container(),
                    resource
                        .container_name()
                        .map(|name| vec![name.to_string()])
                        .unwrap_or_else(|| {
                            resource
                                .child_names()
                                .iter()
                                .map(|name| {
                                    format!("{}:{}", name.parent_id, resource.child_name_at(name))
                                })
                                .collect()
                        }),
                    resource.etag(),
                )
            })
            .collect()
    }

    fn assert_well_formed(cache: &GroupwareResources) {
        assert!(
            cache
                .paths
                .iter()
                .map(|(chunk, path)| chunk.path_str(path))
                .is_sorted_by(|a, b| a < b),
            "the path index must be globally sorted across chunk boundaries"
        );
        assert!(
            cache
                .resources
                .chunks
                .iter()
                .all(|chunk| !chunk.records.is_empty() && chunk.records.len() <= DAV_CHUNK),
            "no resource chunk may be empty or exceed DAV_CHUNK"
        );
        for chunk in cache.paths.chunks.iter() {
            assert!(!chunk.paths.is_empty(), "no path chunk may be empty");
        }
        for is_container in [true, false] {
            let run = if cache.resources.unified_id_space {
                &cache.resources.chunks[..]
            } else if is_container {
                &cache.resources.chunks[..cache.resources.containers_end]
            } else {
                &cache.resources.chunks[cache.resources.containers_end..]
            };
            assert!(
                run.windows(2).all(|pair| pair[0].max_id < pair[1].min_id),
                "chunks within a run must stay ordered and disjoint"
            );
            if cache.resources.unified_id_space {
                break;
            }
        }
    }

    fn assert_matches_cold_build(
        updated: &GroupwareResources,
        specs: &[Spec],
        collection: SyncCollection,
    ) {
        let cold = cold_build(specs, collection);
        assert_well_formed(updated);
        assert_eq!(records(updated), records(&cold), "resource records differ");

        if collection == SyncCollection::FileNode {
            let strip = |entries: Vec<(String, u32, u32, u32)>| {
                entries
                    .into_iter()
                    .map(|(path, document_id, parent_id, seq)| {
                        (path, document_id, parent_id, seq & CONTAINER_FLAG)
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                strip(entries(updated)),
                strip(entries(&cold)),
                "path entries differ"
            );
            for (_, path) in updated.paths.iter() {
                if path.parent_id != NO_ID
                    && let Some((_, parent)) = updated
                        .paths
                        .iter()
                        .find(|(_, other)| other.document_id == path.parent_id)
                {
                    assert!(
                        parent.hierarchy_seq & !CONTAINER_FLAG
                            < path.hierarchy_seq & !CONTAINER_FLAG,
                        "a node must sequence after its parent"
                    );
                }
            }
        } else {
            assert_eq!(entries(updated), entries(&cold), "path entries differ");
        }
    }

    #[test]
    fn calcard_creates_deletes_and_renames_patch_the_index() {
        let base = vec![
            calendar(0, "work"),
            calendar(1, "home"),
            event(0, 0, "a.ics"),
            event(1, 0, "b.ics"),
            event(2, 1, "c.ics"),
        ];
        let cache = cold_build(&base, SyncCollection::Calendar);

        let created = apply(
            &cache,
            SyncCollection::Calendar,
            &[(false, 7, Some(event(7, 1, "new.ics")))],
        );
        let mut specs = base.clone();
        specs.push(event(7, 1, "new.ics"));
        assert_matches_cold_build(&created, &specs, SyncCollection::Calendar);

        let deleted = apply(&created, SyncCollection::Calendar, &[(false, 1, None)]);
        specs.retain(|spec| !matches!(spec, Spec::Event { document_id: 1, .. }));
        assert_matches_cold_build(&deleted, &specs, SyncCollection::Calendar);

        let renamed = apply(
            &deleted,
            SyncCollection::Calendar,
            &[(false, 2, Some(event(2, 1, "renamed.ics")))],
        );
        for spec in specs.iter_mut() {
            if let Spec::Event { document_id: 2, .. } = spec {
                *spec = event(2, 1, "renamed.ics");
            }
        }
        assert_matches_cold_build(&renamed, &specs, SyncCollection::Calendar);
    }

    #[test]
    fn calcard_content_update_shares_the_path_index() {
        let base = vec![calendar(0, "work"), event(0, 0, "a.ics")];
        let cache = cold_build(&base, SyncCollection::Calendar);

        let updated = apply(
            &cache,
            SyncCollection::Calendar,
            &[(false, 0, Some(event(0, 0, "a.ics").with_etag(42)))],
        );

        assert!(
            Arc::ptr_eq(&cache.paths, &updated.paths),
            "a content-only update must keep the path index"
        );
        assert_eq!(updated.resources.find(0, false).unwrap().etag(), 42);
    }

    #[test]
    fn file_content_put_shares_the_path_index() {
        let base = vec![
            folder(0, "docs", None),
            file(1, "readme.txt", Some(0)),
            file(2, "notes.txt", None),
        ];
        let cache = cold_build(&base, SyncCollection::FileNode);

        let updated = apply(
            &cache,
            SyncCollection::FileNode,
            &[(true, 1, Some(file(1, "readme.txt", Some(0)).with_etag(9)))],
        );

        assert!(
            Arc::ptr_eq(&cache.paths, &updated.paths),
            "a file content PUT must keep the path index"
        );
        assert_eq!(updated.resources.find_any(1).unwrap().etag(), 9);
    }

    #[test]
    fn resources_are_reachable_by_document_id() {
        let files = cold_build(
            &[
                folder(0, "docs", None),
                folder(1, "reports", Some(0)),
                file(2, "q1.txt", Some(1)),
                file(3, "readme.txt", None),
            ],
            SyncCollection::FileNode,
        );
        for (document_id, path, is_container) in [
            (0, "docs", true),
            (1, "docs/reports", true),
            (2, "docs/reports/q1.txt", false),
            (3, "readme.txt", false),
        ] {
            let found = files
                .any_resource_path_by_id(document_id)
                .unwrap_or_else(|| panic!("{path} is unreachable by id"));
            assert_eq!(found.path(), path);
            assert_eq!(
                files.container_resource_path_by_id(document_id).is_some(),
                is_container,
                "{path}"
            );
            assert_eq!(
                files
                    .format_resource_paths_by_id(document_id)
                    .collect::<Vec<_>>(),
                vec![files.format_resource(found)],
                "{path}"
            );
        }
        assert!(files.any_resource_path_by_id(9).is_none());
        assert_eq!(
            files.children_ids(0).collect::<Vec<_>>(),
            vec![1],
            "only direct children"
        );

        let calcard = cold_build(
            &[
                calendar(0, "work"),
                calendar(1, "home"),
                event(0, 0, "a.ics"),
                event(1, 1, "b.ics"),
            ],
            SyncCollection::Calendar,
        );
        assert_eq!(
            calcard.container_resource_path_by_id(1).unwrap().path(),
            "home"
        );
        assert_eq!(
            calcard.format_resource_path_by_parent(1, 1).as_deref(),
            Some("/dav/x/john/home/b.ics")
        );
        let mut children = calcard.children_ids(0).collect::<Vec<_>>();
        children.sort_unstable();
        assert_eq!(children, vec![0]);
    }

    #[test]
    fn file_creates_deletes_and_moves_patch_the_index() {
        let mut specs = vec![
            folder(0, "docs", None),
            folder(1, "reports", Some(0)),
            file(2, "q1.txt", Some(1)),
            file(3, "readme.txt", None),
        ];
        let cache = cold_build(&specs, SyncCollection::FileNode);

        let created = apply(
            &cache,
            SyncCollection::FileNode,
            &[(true, 4, Some(file(4, "q2.txt", Some(1))))],
        );
        specs.push(file(4, "q2.txt", Some(1)));
        assert_matches_cold_build(&created, &specs, SyncCollection::FileNode);

        let moved = apply(
            &created,
            SyncCollection::FileNode,
            &[(true, 2, Some(file(2, "q1.txt", Some(0))))],
        );
        for spec in specs.iter_mut() {
            if spec.document_id() == 2 {
                *spec = file(2, "q1.txt", Some(0));
            }
        }
        assert_matches_cold_build(&moved, &specs, SyncCollection::FileNode);

        let deleted = apply(&moved, SyncCollection::FileNode, &[(true, 3, None)]);
        specs.retain(|spec| spec.document_id() != 3);
        assert_matches_cold_build(&deleted, &specs, SyncCollection::FileNode);

        let new_folder = apply(
            &deleted,
            SyncCollection::FileNode,
            &[(true, 5, Some(folder(5, "archive", Some(0))))],
        );
        specs.push(folder(5, "archive", Some(0)));
        assert_matches_cold_build(&new_folder, &specs, SyncCollection::FileNode);
    }

    #[test]
    fn container_changes_fall_back_to_a_full_rebuild() {
        let specs = vec![
            calendar(0, "work"),
            event(0, 0, "a.ics"),
            event(1, 0, "b.ics"),
        ];
        let cache = cold_build(&specs, SyncCollection::Calendar);

        let renamed = apply(
            &cache,
            SyncCollection::Calendar,
            &[(true, 0, Some(calendar(0, "office")))],
        );
        let mut expected = specs.clone();
        expected[0] = calendar(0, "office");
        assert_matches_cold_build(&renamed, &expected, SyncCollection::Calendar);

        let destroyed = apply(&cache, SyncCollection::Calendar, &[(true, 0, None)]);
        assert_matches_cold_build(
            &destroyed,
            &[event(0, 0, "a.ics"), event(1, 0, "b.ics")],
            SyncCollection::Calendar,
        );
    }

    #[test]
    fn the_first_create_lands_in_an_empty_index() {
        let cache = cold_build(&[], SyncCollection::FileNode);
        assert!(cache.paths.is_empty());

        let created = apply(
            &cache,
            SyncCollection::FileNode,
            &[(true, 0, Some(folder(0, "docs", None)))],
        );
        assert_matches_cold_build(
            &created,
            &[folder(0, "docs", None)],
            SyncCollection::FileNode,
        );

        let child = apply(
            &created,
            SyncCollection::FileNode,
            &[(true, 1, Some(file(1, "a.txt", Some(0))))],
        );
        assert_matches_cold_build(
            &child,
            &[folder(0, "docs", None), file(1, "a.txt", Some(0))],
            SyncCollection::FileNode,
        );
    }

    #[test]
    fn scheduling_updates_patch_the_index() {
        let mut specs = vec![
            Spec::Notification {
                document_id: SCHEDULE_OUTBOX_ID,
            },
            Spec::Notification {
                document_id: SCHEDULE_INBOX_ID,
            },
            Spec::Notification { document_id: 1 },
            Spec::Notification { document_id: 2 },
        ];
        let cache = cold_build(&specs, SyncCollection::CalendarEventNotification);

        let created = apply(
            &cache,
            SyncCollection::CalendarEventNotification,
            &[(false, 3, Some(Spec::Notification { document_id: 3 }))],
        );
        specs.push(Spec::Notification { document_id: 3 });
        assert_matches_cold_build(&created, &specs, SyncCollection::CalendarEventNotification);

        let purged = apply(
            &created,
            SyncCollection::CalendarEventNotification,
            &[(false, 1, None), (false, 2, None)],
        );
        specs.retain(|spec| !matches!(spec, Spec::Notification { document_id: 1 | 2 }));
        assert_matches_cold_build(&purged, &specs, SyncCollection::CalendarEventNotification);
    }

    #[test]
    fn a_folder_and_its_child_created_in_one_window() {
        let mut specs = vec![folder(0, "docs", None), file(1, "readme.txt", Some(0))];
        let cache = cold_build(&specs, SyncCollection::FileNode);

        let updated = apply(
            &cache,
            SyncCollection::FileNode,
            &[
                (true, 2, Some(folder(2, "reports", Some(0)))),
                (true, 3, Some(file(3, "q1.txt", Some(2)))),
            ],
        );
        specs.push(folder(2, "reports", Some(0)));
        specs.push(file(3, "q1.txt", Some(2)));
        assert_matches_cold_build(&updated, &specs, SyncCollection::FileNode);
        assert_eq!(
            updated.any_resource_path_by_id(3).unwrap().path(),
            "docs/reports/q1.txt"
        );
    }

    #[test]
    fn a_file_moved_into_a_folder_created_in_one_window() {
        let mut specs = vec![folder(0, "docs", None), file(1, "a.txt", None)];
        let cache = cold_build(&specs, SyncCollection::FileNode);

        let updated = apply(
            &cache,
            SyncCollection::FileNode,
            &[
                (true, 2, Some(folder(2, "inbox", Some(0)))),
                (true, 1, Some(file(1, "a.txt", Some(2)))),
            ],
        );
        specs.push(folder(2, "inbox", Some(0)));
        specs[1] = file(1, "a.txt", Some(2));
        assert_matches_cold_build(&updated, &specs, SyncCollection::FileNode);
        assert_eq!(
            updated.any_resource_path_by_id(1).unwrap().path(),
            "docs/inbox/a.txt"
        );
        assert!(updated.by_path("a.txt").is_none());
    }

    #[test]
    fn a_container_flip_rebuilds_the_index() {
        let mut specs = vec![
            folder(0, "docs", None),
            file(1, "notes", Some(0)),
            folder(2, "old", None),
        ];
        let cache = cold_build(&specs, SyncCollection::FileNode);

        let to_folder = apply(
            &cache,
            SyncCollection::FileNode,
            &[(true, 1, Some(folder(1, "notes", Some(0))))],
        );
        specs[1] = folder(1, "notes", Some(0));
        assert_matches_cold_build(&to_folder, &specs, SyncCollection::FileNode);
        assert!(to_folder.container_resource_path_by_id(1).is_some());

        let to_file = apply(
            &to_folder,
            SyncCollection::FileNode,
            &[(true, 2, Some(file(2, "old", None)))],
        );
        specs[2] = file(2, "old", None);
        assert_matches_cold_build(&to_file, &specs, SyncCollection::FileNode);
        assert!(to_file.container_resource_path_by_id(2).is_none());
        assert_eq!(to_file.any_resource_path_by_id(2).unwrap().path(), "old");
    }

    #[test]
    fn a_two_name_item_moved_between_calendars() {
        let two_names = |names: &[(u32, &str)]| Spec::Event {
            document_id: 5,
            names: names
                .iter()
                .map(|(parent_id, name)| (*parent_id, name.to_string()))
                .collect(),
            etag: 0,
        };
        let mut specs = vec![
            calendar(0, "work"),
            calendar(1, "home"),
            calendar(2, "shared"),
            event(3, 0, "x.ics"),
            two_names(&[(0, "a.ics"), (1, "a.ics")]),
        ];
        let cache = cold_build(&specs, SyncCollection::Calendar);

        let moved = apply(
            &cache,
            SyncCollection::Calendar,
            &[(false, 5, Some(two_names(&[(1, "a.ics"), (2, "b.ics")])))],
        );
        specs[4] = two_names(&[(1, "a.ics"), (2, "b.ics")]);
        assert_matches_cold_build(&moved, &specs, SyncCollection::Calendar);
        assert!(moved.by_path("work/a.ics").is_none());
        assert_eq!(
            moved.format_resource_path_by_parent(5, 2).as_deref(),
            Some("/dav/x/john/shared/b.ics")
        );
        let mut paths = moved.format_resource_paths_by_id(5).collect::<Vec<_>>();
        paths.sort();
        assert_eq!(
            paths,
            vec!["/dav/x/john/home/a.ics", "/dav/x/john/shared/b.ics"]
        );
    }

    #[test]
    fn a_file_container_delete_with_children() {
        let mut specs = vec![
            folder(0, "docs", None),
            folder(1, "reports", Some(0)),
            file(2, "q1.txt", Some(1)),
            folder(3, "drafts", Some(1)),
            file(4, "readme.txt", Some(0)),
        ];
        let cache = cold_build(&specs, SyncCollection::FileNode);

        let deleted = apply(
            &cache,
            SyncCollection::FileNode,
            &[(true, 1, None), (true, 2, None), (true, 3, None)],
        );
        specs.retain(|spec| !matches!(spec.document_id(), 1..=3));
        assert_matches_cold_build(&deleted, &specs, SyncCollection::FileNode);
        assert!(deleted.by_path("docs/reports").is_none());
        assert_eq!(deleted.children_ids(0).collect::<Vec<_>>(), vec![4]);
        assert_eq!(deleted.subtree("docs").count(), 2);
    }

    #[test]
    fn warm_creates_split_oversized_chunks() {
        let mut specs = (0..DAV_CHUNK as u32)
            .map(|document_id| file(document_id, &format!("f{document_id:07}.txt"), None))
            .collect::<Vec<_>>();
        let mut cache = cold_build(&specs, SyncCollection::FileNode);
        assert_eq!(cache.resources.chunks.len(), 1);

        for document_id in DAV_CHUNK as u32..DAV_CHUNK as u32 + 300 {
            let spec = file(document_id, &format!("f{document_id:07}.txt"), None);
            cache = apply(
                &cache,
                SyncCollection::FileNode,
                &[(true, document_id, Some(spec.clone()))],
            );
            specs.push(spec);
        }

        assert!(
            cache.resources.chunks.len() > 1,
            "the tail chunk must have been split"
        );
        assert_matches_cold_build(&cache, &specs, SyncCollection::FileNode);
    }
}
