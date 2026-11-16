/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    ItemDelta, MessageCache, MessageStoreCache, MessageUpdateLock, MessagesCache, Server,
    Verification,
    cache::{
        refresh::MAX_DELTA_IDS,
        swap::{BLOCKING_CODEC_THRESHOLD, SwapKey, writer::SwapChanges},
    },
};
use email::{KeywordWrites, full_email_cache_build, update_email_cache};
use mailbox::{full_mailbox_cache_build, update_mailbox_cache};
use std::{collections::hash_map::Entry, sync::Arc, time::Instant};
use store::{
    ahash::AHashMap,
    query::log::{Change, Changes, Query},
    write::AssignedIds,
};
use trc::{AddContext, CacheEvent};
use types::collection::SyncCollection;

pub mod email;
pub mod mailbox;

pub trait MessageCacheFetch: Sync + Send {
    fn get_cached_messages(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<MessageStoreCache>>> + Send;

    fn get_resident_messages(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<Arc<MessageStoreCache>>>> + Send;

    fn fresh_messages(&self, account_id: u32) -> Option<Arc<MessageStoreCache>>;

    fn apply_keyword_writes(
        &self,
        account_id: u32,
        cache: &Arc<MessageStoreCache>,
        writes: &KeywordWrites,
        assigned_ids: &AssignedIds,
    ) -> bool;
}

impl MessageCacheFetch for Server {
    fn fresh_messages(&self, account_id: u32) -> Option<Arc<MessageStoreCache>> {
        let caches = &self.inner.cache;
        caches
            .peek_messages(account_id)
            .filter(|cache| cache.is_fresh(&caches.revalidate))
    }

    async fn get_cached_messages(&self, account_id: u32) -> trc::Result<Arc<MessageStoreCache>> {
        let cache = match self.inner.cache.resident_messages(account_id) {
            Some(cache) => cache,
            None => match load_cache(self, account_id).await? {
                LoadedCache::Resident(cache) => cache,
                LoadedCache::Built(cache) => return Ok(cache),
            },
        };
        revalidate_messages(self, account_id, cache).await
    }

    async fn get_resident_messages(
        &self,
        account_id: u32,
    ) -> trc::Result<Option<Arc<MessageStoreCache>>> {
        match self.inner.cache.resident_messages(account_id) {
            Some(cache) => revalidate_messages(self, account_id, cache).await.map(Some),
            None => Ok(None),
        }
    }

    fn apply_keyword_writes(
        &self,
        account_id: u32,
        cache: &Arc<MessageStoreCache>,
        writes: &KeywordWrites,
        assigned_ids: &AssignedIds,
    ) -> bool {
        let start_time = Instant::now();
        let change_ids = assigned_ids
            .change_ids(account_id, SyncCollection::Email)
            .collect::<Vec<_>>();
        let (Some(&last_change_id), Some(last_write)) = (change_ids.last(), writes.writes().last())
        else {
            return false;
        };
        if last_write.commit_point as usize + 1 != change_ids.len()
            || !change_ids
                .iter()
                .copied()
                .eq(cache.last_change_id + 1..=last_change_id)
        {
            return false;
        }

        let caches = &self.inner.cache;
        let Some(_permit) = cache.update_lock.try_update() else {
            return false;
        };
        if !caches
            .peek_messages(account_id)
            .is_some_and(|resident| Arc::ptr_eq(&resident, cache))
        {
            return false;
        }

        let mut patches = Vec::with_capacity(writes.writes().len());
        for write in writes.writes() {
            let Some(message) = cache
                .emails
                .at(write.position)
                .filter(|message| message.document_id() == write.document_id)
            else {
                return false;
            };
            if message.keywords() != write.keywords {
                let Some(&change_id) = change_ids.get(write.commit_point as usize) else {
                    return false;
                };
                patches.push((
                    write.position,
                    MessageCache::new(
                        write.document_id,
                        message.mailboxes().iter().copied().collect(),
                        write.keywords,
                        message.thread_id(),
                        change_id,
                        message.size(),
                        message.received_at(),
                        message.sent_at(),
                    ),
                ));
            }
        }

        let refresh = if writes.writes().len() <= MAX_DELTA_IDS {
            let mut view_ids = writes
                .writes()
                .iter()
                .map(|write| write.document_id)
                .collect::<Vec<_>>();
            view_ids.sort_unstable();
            view_ids.dedup();
            ItemDelta::new(cache.emails.change_id, last_change_id, &view_ids)
                .map(|delta| cache.refresh.advance(delta))
        } else {
            None
        }
        .unwrap_or_default();

        let emails = cache
            .emails
            .patch(last_change_id, &patches, cache.emails.shared_keywords());
        let mailboxes = if writes.mailboxes_changed() {
            let mut mailboxes = cache.mailboxes.as_ref().clone();
            mailboxes.change_id = last_change_id;
            Arc::new(mailboxes)
        } else {
            cache.mailboxes.clone()
        };
        let updated = Arc::new(MessageStoreCache {
            size: emails.size + mailboxes.size,
            emails: Arc::new(emails),
            mailboxes,
            update_lock: cache.update_lock.clone(),
            refresh: Arc::new(refresh),
            last_change_id,
            verification: Verification::default(),
        });
        caches.publish_messages(
            account_id,
            &updated,
            Some(SwapChanges::applied(
                writes.writes().len(),
                cache.last_change_id,
                last_change_id,
                updated.emails.len(),
            )),
        );

        trc::event!(
            Cache(CacheEvent::Update),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            ChangeId = last_change_id,
            Details = vec![writes.writes().len(), 0],
            Total = vec![updated.emails.len(), updated.mailboxes.items.len()],
            Elapsed = start_time.elapsed(),
        );

        true
    }
}

async fn revalidate_messages(
    server: &Server,
    account_id: u32,
    cache: Arc<MessageStoreCache>,
) -> trc::Result<Arc<MessageStoreCache>> {
    let caches = &server.inner.cache;

    // Serve the snapshot without revalidating while it is within the freshness window
    let start_time = Instant::now();
    let revalidate = &caches.revalidate;
    let served = |cache: Arc<MessageStoreCache>| {
        trc::event!(
            Cache(CacheEvent::Hit),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            ChangeId = cache.last_change_id,
            Elapsed = start_time.elapsed(),
        );
        Ok(cache)
    };
    if cache.is_fresh(revalidate) {
        return served(cache);
    }

    let lock = cache.update_lock.clone();
    let entry_epoch = lock.epoch();
    let (_permit, cache) = match lock.try_update() {
        Some(permit) => (permit, cache),
        None => loop {
            let released = lock.released();
            let permit = lock.try_update();
            if permit.is_none() {
                released.await;
            }
            match (caches.peek_messages(account_id), permit) {
                (Some(current), _)
                    if current.is_fresh(revalidate)
                        || (Arc::ptr_eq(&current.update_lock, &lock)
                            && current
                                .verification
                                .is_verified_since(entry_epoch, revalidate)) =>
                {
                    return served(current);
                }
                (current, Some(permit)) => break (permit, current.unwrap_or(cache)),
                _ => {}
            }
        },
    };

    // Obtain current state
    let verification = Verification::capture(revalidate, &cache.update_lock);
    let changes = server
        .core
        .storage
        .data
        .changes(
            account_id,
            SyncCollection::Email.into(),
            Query::Since(cache.last_change_id),
        )
        .await
        .caused_by(trc::location!())?;

    // Regenerate cache if the change log has been truncated
    if changes.needs_full_rebuild(cache.last_change_id) {
        let mut cache =
            full_cache_build(server, account_id, cache.update_lock.clone(), verification).await?;
        if !is_resident_lock(server, account_id, &cache.update_lock)
            && let Some(cache) = Arc::get_mut(&mut cache)
        {
            cache.verification = Verification::default();
        }
        caches.publish_messages(
            account_id,
            &cache,
            Some(SwapChanges::rebuilt(
                cache.last_change_id,
                cache.emails.len(),
            )),
        );

        trc::event!(
            Cache(CacheEvent::Stale),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            ChangeId = cache.last_change_id,
            Total = vec![cache.emails.len(), cache.mailboxes.items.len()],
            Elapsed = start_time.elapsed(),
        );

        return Ok(cache);
    }

    // Verify changes
    if changes.changes.is_empty() {
        let is_current = verification.is_current(&cache.update_lock);
        let is_advanced = changes.to_change_id > cache.last_change_id;
        let cache = if is_current || is_advanced {
            let mut verified = cache.as_ref().clone();
            if is_current && is_resident_lock(server, account_id, &verified.update_lock) {
                verified.verification = verification;
            }
            if is_advanced {
                verified.last_change_id = changes.to_change_id;
                if changes.item_change_id.is_some() {
                    verified.refresh = Arc::new(verified.refresh.with_new_uid_next());
                }
            }
            let verified = Arc::new(verified);
            caches.publish_messages(account_id, &verified, None);
            verified
        } else {
            cache
        };

        trc::event!(
            Cache(CacheEvent::Hit),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            ChangeId = cache.last_change_id,
            Elapsed = start_time.elapsed(),
        );

        return Ok(cache);
    }

    let change_set = ChangeSet::classify(changes);
    let base_change_id = cache.last_change_id;
    let mut cache = change_set.apply(server, account_id, cache.as_ref()).await?;
    if is_resident_lock(server, account_id, &cache.update_lock) {
        cache.verification = verification;
    }

    let cache = Arc::new(cache);
    caches.publish_messages(
        account_id,
        &cache,
        Some(SwapChanges::applied(
            change_set.items.len(),
            base_change_id,
            cache.last_change_id,
            cache.emails.len(),
        )),
    );

    trc::event!(
        Cache(CacheEvent::Update),
        AccountId = account_id,
        Collection = SyncCollection::Email.as_str(),
        ChangeId = cache.last_change_id,
        Details = vec![change_set.items.len(), change_set.containers.len()],
        Total = vec![cache.emails.len(), cache.mailboxes.items.len()],
        Elapsed = start_time.elapsed(),
    );

    Ok(cache)
}

struct ChangeSet {
    items: AHashMap<u32, bool>,
    containers: AHashMap<u32, bool>,
    view_ids: Vec<u32>,
    has_container_property_changes: bool,
    item_change_id: Option<u64>,
    container_change_id: Option<u64>,
    to_change_id: u64,
}

impl ChangeSet {
    fn classify(changes: Changes) -> Self {
        let mut items: AHashMap<u32, bool> = AHashMap::with_capacity(changes.changes.len());
        let mut containers: AHashMap<u32, bool> = AHashMap::with_capacity(changes.changes.len());
        let mut view_ids = Vec::with_capacity(changes.changes.len());
        let mut has_container_property_changes = false;

        for change in changes.changes {
            match change {
                Change::InsertItem(id) => {
                    view_ids.push(id as u32);
                    match items.entry(id as u32) {
                        Entry::Occupied(mut entry) => {
                            *entry.get_mut() = true;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(true);
                        }
                    }
                }
                Change::UpdateItem(id) => {
                    view_ids.push(id as u32);
                    items.insert(id as u32, true);
                }
                Change::UpdateItemMetadata(id) => {
                    items.insert(id as u32, true);
                }
                Change::DeleteItem(id) => {
                    view_ids.push(id as u32);
                    match items.entry(id as u32) {
                        Entry::Occupied(mut entry) => {
                            // Thread reassignment
                            *entry.get_mut() = true;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(false);
                        }
                    }
                }
                Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                    containers.insert(id as u32, true);
                }
                Change::DeleteContainer(id) => {
                    containers.insert(id as u32, false);
                }
                Change::UpdateContainerPartial(id, partial) => {
                    if partial.has_metadata() {
                        containers.insert(id as u32, true);
                    } else {
                        has_container_property_changes = true;
                    }
                }
            }
        }

        view_ids.sort_unstable();
        view_ids.dedup();

        ChangeSet {
            items,
            containers,
            view_ids,
            has_container_property_changes,
            item_change_id: changes.item_change_id,
            container_change_id: changes.container_change_id,
            to_change_id: changes.to_change_id,
        }
    }

    async fn apply(
        &self,
        server: &Server,
        account_id: u32,
        previous: &MessageStoreCache,
    ) -> trc::Result<MessageStoreCache> {
        let mut cache = previous.clone();

        if !self.items.is_empty() {
            let mut email_cache =
                update_email_cache(server, account_id, &self.items, &cache).await?;
            email_cache.change_id = self.item_change_id.unwrap_or(self.to_change_id);
            cache.refresh = Arc::new(
                ItemDelta::new(
                    previous.emails.change_id,
                    email_cache.change_id,
                    &self.view_ids,
                )
                .map(|delta| previous.refresh.advance(delta))
                .unwrap_or_default(),
            );
            cache.emails = Arc::new(email_cache);
        } else if self.item_change_id.is_some()
            || !self.containers.is_empty()
            || self.has_container_property_changes
        {
            cache.refresh = Arc::new(previous.refresh.with_new_uid_next());
        }

        if !self.containers.is_empty() {
            let mut mailbox_cache =
                update_mailbox_cache(server, account_id, &self.containers, &cache.mailboxes)
                    .await?;
            mailbox_cache.change_id = self.container_change_id.unwrap_or(self.to_change_id);
            cache.mailboxes = Arc::new(mailbox_cache);
        } else if self.has_container_property_changes {
            let mut mailbox_cache = cache.mailboxes.as_ref().clone();
            mailbox_cache.change_id = self.container_change_id.unwrap_or(self.to_change_id);
            cache.mailboxes = Arc::new(mailbox_cache);
        }

        cache.size = cache.emails.size + cache.mailboxes.size;
        cache.last_change_id = self.to_change_id;

        Ok(cache)
    }
}

fn is_resident_lock(
    server: &Server,
    account_id: u32,
    update_lock: &Arc<MessageUpdateLock>,
) -> bool {
    server
        .inner
        .cache
        .peek_messages(account_id)
        .is_some_and(|resident| Arc::ptr_eq(&resident.update_lock, update_lock))
}

enum LoadedCache {
    Resident(Arc<MessageStoreCache>),
    Built(Arc<MessageStoreCache>),
}

async fn load_cache(server: &Server, account_id: u32) -> trc::Result<LoadedCache> {
    Box::pin(load_missing_cache(server, account_id)).await
}

async fn load_missing_cache(server: &Server, account_id: u32) -> trc::Result<LoadedCache> {
    let caches = &server.inner.cache;
    let guard = match caches.messages.get_value_or_guard_async(&account_id).await {
        Ok(cache) => return Ok(LoadedCache::Resident(cache)),
        Err(guard) => guard,
    };

    if let Some(cache) = caches.messages_large.lookup(account_id) {
        drop(guard);
        return Ok(LoadedCache::Resident(cache));
    }

    let start_time = Instant::now();
    if let Some(cache) = restore_cache_build(server, account_id).await {
        caches.publish_loaded_messages(guard, account_id, &cache, None);
        return Ok(LoadedCache::Resident(cache));
    }

    let cache = full_cache_build(server, account_id, Arc::default(), Default::default()).await?;
    caches.publish_loaded_messages(
        guard,
        account_id,
        &cache,
        Some(SwapChanges::rebuilt(
            cache.last_change_id,
            cache.emails.len(),
        )),
    );

    trc::event!(
        Cache(CacheEvent::Miss),
        AccountId = account_id,
        Collection = SyncCollection::Email.as_str(),
        Total = vec![cache.emails.len(), cache.mailboxes.items.len()],
        ChangeId = cache.last_change_id,
        Elapsed = start_time.elapsed(),
    );

    Ok(LoadedCache::Built(cache))
}

async fn restore_cache_build(server: &Server, account_id: u32) -> Option<Arc<MessageStoreCache>> {
    if !server.inner.cache.swap.is_enabled() {
        return None;
    }

    Box::pin(restore_swapped_cache(server, account_id)).await
}

async fn restore_swapped_cache(server: &Server, account_id: u32) -> Option<Arc<MessageStoreCache>> {
    let start_time = Instant::now();
    let snapshot = match server
        .inner
        .cache
        .swap
        .load(SwapKey::messages(account_id))
        .await
    {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return None,
        Err(err) => {
            trc::error!(
                err.details("Failed to read the message cache snapshot")
                    .ctx(trc::Key::AccountId, account_id)
            );
            return None;
        }
    };

    let snapshot_len = snapshot.len();
    let emails = if snapshot_len >= BLOCKING_CODEC_THRESHOLD {
        tokio::task::spawn_blocking(move || MessagesCache::from_snapshot(&snapshot))
            .await
            .ok()
            .flatten()
    } else {
        MessagesCache::from_snapshot(&snapshot)
    }
    .or_else(|| {
        trc::event!(
            Cache(CacheEvent::SwapMiss),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            Details = "Discarded an unreadable message cache snapshot",
        );
        None
    })?;

    let snapshot_change_id = emails.change_id;
    let mailboxes = full_mailbox_cache_build(server, account_id, snapshot_change_id)
        .await
        .caused_by(trc::location!())
        .inspect_err(|err| {
            trc::error!(err.clone());
        })
        .ok()?;

    let size = emails.size + mailboxes.size;
    let cache = MessageStoreCache {
        update_lock: Arc::default(),
        refresh: Default::default(),
        emails: Arc::new(emails),
        mailboxes: Arc::new(mailboxes),
        last_change_id: snapshot_change_id,
        size,
        verification: Default::default(),
    };

    trc::event!(
        Cache(CacheEvent::SwapHit),
        AccountId = account_id,
        Collection = SyncCollection::Email.as_str(),
        ChangeId = snapshot_change_id,
        Total = vec![cache.emails.len(), cache.mailboxes.items.len()],
        Size = snapshot_len,
        Elapsed = start_time.elapsed(),
    );

    Some(Arc::new(cache))
}

async fn full_cache_build(
    server: &Server,
    account_id: u32,
    update_lock: Arc<MessageUpdateLock>,
    verification: Verification,
) -> trc::Result<Arc<MessageStoreCache>> {
    Box::pin(build_full_cache(
        server,
        account_id,
        update_lock,
        verification,
    ))
    .await
}

async fn build_full_cache(
    server: &Server,
    account_id: u32,
    update_lock: Arc<MessageUpdateLock>,
    verification: Verification,
) -> trc::Result<Arc<MessageStoreCache>> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::Email.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let mailboxes = full_mailbox_cache_build(server, account_id, last_change_id).await?;
    let last_change_id = mailboxes.change_id;
    let mut emails = full_email_cache_build(server, account_id).await?;
    let size = emails.size + mailboxes.size;
    emails.change_id = last_change_id;

    Ok(Arc::new(MessageStoreCache {
        update_lock,
        refresh: Default::default(),
        emails: Arc::new(emails),
        mailboxes: Arc::new(mailboxes),
        last_change_id,
        size,
        verification,
    }))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/cache/tests.rs"]
mod tests;
