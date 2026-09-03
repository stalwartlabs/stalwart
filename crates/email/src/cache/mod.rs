/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    MessageStoreCache, MessagesCache, Server, UpdateLock,
    cache::{
        LockResult,
        swap::{BLOCKING_CODEC_THRESHOLD, SwapKey},
    },
};
use email::{full_email_cache_build, update_email_cache};
use mailbox::{full_mailbox_cache_build, update_mailbox_cache};
use std::{collections::hash_map::Entry, sync::Arc, time::Instant};
use store::{
    ahash::AHashMap,
    query::log::{Change, Changes, Query},
};
use trc::{AddContext, StoreEvent};
use types::collection::SyncCollection;

pub mod email;
pub mod mailbox;

pub trait MessageCacheFetch: Sync + Send {
    fn get_cached_messages(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<MessageStoreCache>>> + Send;
}

impl MessageCacheFetch for Server {
    async fn get_cached_messages(&self, account_id: u32) -> trc::Result<Arc<MessageStoreCache>> {
        let cache_store = &self.inner.cache.messages;
        let mut cache = match cache_store.get_value_or_guard_async(&account_id).await {
            Ok(cache) => cache,
            Err(guard) => {
                let start_time = Instant::now();
                match restore_cache_build(self, account_id).await {
                    Some(cache) => {
                        if admit(self, account_id, &cache) {
                            let _ = guard.insert(cache.clone());
                        }
                        cache
                    }
                    None => {
                        let cache =
                            full_cache_build(self, account_id, Arc::new(UpdateLock::new())).await?;

                        if admit(self, account_id, &cache) {
                            let _ = guard.insert(cache.clone());
                            self.inner.cache.swap.notify_changed(
                                account_id,
                                SyncCollection::Email,
                                cache.emails.len() as u32,
                            );
                        } else {
                            self.inner.cache.swap.notify_refresh_messages(
                                account_id,
                                cache.emails.len() as u32,
                                &cache,
                            );
                        }

                        trc::event!(
                            Store(StoreEvent::CacheMiss),
                            AccountId = account_id,
                            Collection = SyncCollection::Email.as_str(),
                            Total = vec![cache.emails.len(), cache.mailboxes.items.len()],
                            ChangeId = cache.last_change_id,
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
                SyncCollection::Email.into(),
                Query::Since(cache.last_change_id),
            )
            .await
            .caused_by(trc::location!())?;

        // Regenerate cache if the change log has been truncated
        if changes.is_truncated {
            let lock = cache.update_lock.clone();
            let _permit = match lock.acquire(cache.last_change_id).await? {
                LockResult::Acquired(permit) => permit,
                LockResult::Stale(permit) => {
                    let rebuilt = cache_store.peek(&account_id).unwrap_or(cache.clone());
                    if rebuilt.last_change_id >= changes.to_change_id {
                        trc::event!(
                            Store(StoreEvent::CacheHit),
                            AccountId = account_id,
                            Collection = SyncCollection::Email.as_str(),
                            ChangeId = rebuilt.last_change_id,
                            Elapsed = start_time.elapsed(),
                        );
                        return Ok(rebuilt);
                    }

                    permit
                }
            };

            let cache = full_cache_build(self, account_id, lock.clone()).await?;
            if admit(self, account_id, &cache) {
                cache_store.update(account_id, cache.clone());
                self.inner.cache.swap.notify_changed(
                    account_id,
                    SyncCollection::Email,
                    cache.emails.len() as u32,
                );
            } else {
                cache_store.remove(&account_id);
                self.inner.cache.swap.notify_refresh_messages(
                    account_id,
                    cache.emails.len() as u32,
                    &cache,
                );
            }

            trc::event!(
                Store(StoreEvent::CacheStale),
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
            trc::event!(
                Store(StoreEvent::CacheHit),
                AccountId = account_id,
                Collection = SyncCollection::Email.as_str(),
                ChangeId = cache.last_change_id,
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Lock for updates
        let lock = cache.update_lock.clone();
        let _permit = match lock.acquire(cache.last_change_id).await? {
            LockResult::Acquired(permit) => permit,
            LockResult::Stale(permit) => {
                cache = cache_store.peek(&account_id).unwrap_or(cache.clone());
                if cache.last_change_id >= changes.to_change_id {
                    trc::event!(
                        Store(StoreEvent::CacheHit),
                        AccountId = account_id,
                        Collection = SyncCollection::Email.as_str(),
                        ChangeId = cache.last_change_id,
                        Elapsed = start_time.elapsed(),
                    );
                    return Ok(cache);
                }

                permit
            }
        };
        let change_set = ChangeSet::classify(changes);
        let cache = change_set.apply(self, account_id, cache.as_ref()).await?;

        let cache = Arc::new(cache);
        if admit(self, account_id, &cache) {
            cache_store.update(account_id, cache.clone());
            self.inner.cache.swap.notify_changed(
                account_id,
                SyncCollection::Email,
                change_set.items.len() as u32,
            );
        } else {
            cache_store.remove(&account_id);
            self.inner.cache.swap.notify_refresh_messages(
                account_id,
                change_set.items.len() as u32,
                &cache,
            );
        }

        trc::event!(
            Store(StoreEvent::CacheUpdate),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            ChangeId = cache.last_change_id,
            Details = vec![change_set.items.len(), change_set.containers.len()],
            Total = vec![cache.emails.len(), cache.mailboxes.items.len()],
            Elapsed = start_time.elapsed(),
        );

        Ok(cache)
    }
}

struct ChangeSet {
    items: AHashMap<u32, bool>,
    containers: AHashMap<u32, bool>,
    has_container_property_changes: bool,
    item_change_id: Option<u64>,
    container_change_id: Option<u64>,
    to_change_id: u64,
}

impl ChangeSet {
    fn classify(changes: Changes) -> Self {
        let mut items: AHashMap<u32, bool> = AHashMap::with_capacity(changes.changes.len());
        let mut containers: AHashMap<u32, bool> = AHashMap::with_capacity(changes.changes.len());
        let mut has_container_property_changes = false;

        for change in changes.changes {
            match change {
                Change::InsertItem(id) => match items.entry(id as u32) {
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() = true;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(true);
                    }
                },
                Change::UpdateItem(id) => {
                    items.insert(id as u32, true);
                }
                Change::DeleteItem(id) => {
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
                Change::UpdateContainerProperty(_) => {
                    has_container_property_changes = true;
                }
            }
        }

        ChangeSet {
            items,
            containers,
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
            cache.emails = Arc::new(email_cache);
        }

        if !self.containers.is_empty() {
            let mut mailbox_cache =
                update_mailbox_cache(server, account_id, &self.containers, &cache).await?;
            mailbox_cache.change_id = self.container_change_id.unwrap_or(self.to_change_id);
            cache.mailboxes = Arc::new(mailbox_cache);
        } else if self.has_container_property_changes {
            let mut mailbox_cache = cache.mailboxes.as_ref().clone();
            mailbox_cache.change_id = self.container_change_id.unwrap_or(self.to_change_id);
            cache.mailboxes = Arc::new(mailbox_cache);
        }

        cache.size = cache.emails.size + cache.mailboxes.size;
        cache.last_change_id = self.to_change_id;
        cache.update_lock.set_revision(cache.last_change_id);

        Ok(cache)
    }
}

#[inline(always)]
fn admit(server: &Server, account_id: u32, cache: &Arc<MessageStoreCache>) -> bool {
    let cache_store = &server.inner.cache.messages;
    if !cache_store.is_oversized(&account_id, cache) {
        return true;
    }

    trc::event!(
        Store(StoreEvent::CacheEntryTooLarge),
        AccountId = account_id,
        Collection = SyncCollection::Email.as_str(),
        Size = cache.size,
        Limit = cache_store.admission_limit(),
    );
    false
}

async fn restore_cache_build(server: &Server, account_id: u32) -> Option<Arc<MessageStoreCache>> {
    if !server.inner.cache.swap.is_enabled() {
        return None;
    }

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
            Store(StoreEvent::SwapMiss),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            Details = "Discarded an unreadable message cache snapshot",
        );
        None
    })?;

    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::Email.into())
        .await
        .caused_by(trc::location!())
        .inspect_err(|err| {
            trc::error!(err.clone());
        })
        .ok()?
        .unwrap_or_default();

    if emails.change_id > last_change_id {
        trc::event!(
            Store(StoreEvent::SwapMiss),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            ChangeId = emails.change_id,
            Details = "Discarded a message cache snapshot newer than the change log",
        );
        return None;
    }

    let snapshot_change_id = emails.change_id;
    let mut mailboxes = full_mailbox_cache_build(server, account_id)
        .await
        .caused_by(trc::location!())
        .inspect_err(|err| {
            trc::error!(err.clone());
        })
        .ok()?;
    mailboxes.change_id = snapshot_change_id;

    let update_lock = Arc::new(UpdateLock::new());
    update_lock.set_revision(snapshot_change_id);
    let size = emails.size + mailboxes.size;
    let cache = MessageStoreCache {
        update_lock,
        emails: Arc::new(emails),
        mailboxes: Arc::new(mailboxes),
        last_change_id: snapshot_change_id,
        size,
    };

    trc::event!(
        Store(StoreEvent::SwapHit),
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
    update_lock: Arc<UpdateLock>,
) -> trc::Result<Arc<MessageStoreCache>> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::Email.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let mut emails = full_email_cache_build(server, account_id).await?;
    let mut mailboxes = full_mailbox_cache_build(server, account_id).await?;
    let size = emails.size + mailboxes.size;
    emails.change_id = last_change_id;
    mailboxes.change_id = last_change_id;
    update_lock.set_revision(last_change_id);

    Ok(Arc::new(MessageStoreCache {
        update_lock,
        emails: Arc::new(emails),
        mailboxes: Arc::new(mailboxes),
        last_change_id,
        size,
    }))
}
