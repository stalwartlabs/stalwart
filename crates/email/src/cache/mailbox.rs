/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::MessageCacheFetch;
use crate::mailbox::{ArchivedMailbox, Mailbox, manage::MailboxFnc};
use common::{
    MailboxCache, MailboxesCache, MessageStoreCache, Server, auth::AccessToken,
    sharing::EffectiveAcl,
};
use std::sync::Arc;
use store::{
    ValueKey,
    query::log::{Change, Query},
    write::{Archive, ArchiveBytes},
};
use store::{ahash::AHashMap, roaring::RoaringBitmap};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
    field::Field,
    special_use::SpecialUse,
};
use utils::{map::bitmap::Bitmap, topological::TopologicalSort};

#[derive(Debug, Clone)]
pub struct AccountMailboxes {
    pub mailboxes: Arc<MailboxesCache>,
    pub change_id: u64,
}

pub trait MailboxCacheFetch: Sync + Send {
    fn fetch_mailboxes(
        &self,
        account_id: u32,
        known: Option<&AccountMailboxes>,
    ) -> impl Future<Output = trc::Result<AccountMailboxes>> + Send;
}

impl MailboxCacheFetch for Server {
    async fn fetch_mailboxes(
        &self,
        account_id: u32,
        known: Option<&AccountMailboxes>,
    ) -> trc::Result<AccountMailboxes> {
        if let Some(cache) = self.get_resident_messages(account_id).await? {
            return Ok(AccountMailboxes {
                mailboxes: cache.mailboxes.clone(),
                change_id: cache.last_change_id,
            });
        }

        let Some(known) = known else {
            return build_account_mailboxes(self, account_id).await;
        };
        let changes = self
            .core
            .storage
            .data
            .changes(
                account_id,
                SyncCollection::Email.into(),
                Query::Since(known.change_id),
            )
            .await
            .caused_by(trc::location!())?;
        if changes.needs_full_rebuild(known.change_id) {
            return build_account_mailboxes(self, account_id).await;
        }

        let mut changed_ids = AHashMap::new();
        for change in &changes.changes {
            match change {
                Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                    changed_ids.insert(*id as u32, true);
                }
                Change::UpdateContainerPartial(id, partial) if partial.has_metadata() => {
                    changed_ids.insert(*id as u32, true);
                }
                Change::DeleteContainer(id) => {
                    changed_ids.insert(*id as u32, false);
                }
                _ => {}
            }
        }

        let change_id = changes.to_change_id.max(known.change_id);
        if changed_ids.is_empty() {
            return Ok(AccountMailboxes {
                mailboxes: known.mailboxes.clone(),
                change_id,
            });
        }

        let mut mailboxes = update_mailbox_cache(self, account_id, &changed_ids, &known.mailboxes)
            .await
            .caused_by(trc::location!())?;
        mailboxes.change_id = changes.container_change_id.unwrap_or(change_id);
        Ok(AccountMailboxes {
            mailboxes: Arc::new(mailboxes),
            change_id,
        })
    }
}

async fn build_account_mailboxes(
    server: &Server,
    account_id: u32,
) -> trc::Result<AccountMailboxes> {
    let change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::Email.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let mailboxes = full_mailbox_cache_build(server, account_id, change_id).await?;
    Ok(AccountMailboxes {
        change_id: mailboxes.change_id,
        mailboxes: Arc::new(mailboxes),
    })
}

struct MailboxesCacheBuilder {
    pub change_id: u64,
    pub index: AHashMap<u32, u32>,
    pub items: Vec<MailboxCache>,
    pub size: u64,
}

pub(crate) async fn update_mailbox_cache(
    server: &Server,
    account_id: u32,
    changed_ids: &AHashMap<u32, bool>,
    mailboxes: &MailboxesCache,
) -> trc::Result<MailboxesCache> {
    let mut changes = Vec::with_capacity(changed_ids.len());
    for (document_id, is_update) in changed_ids {
        if *is_update
            && let Some(archive) = server
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Mailbox,
                    *document_id,
                ))
                .await
                .caused_by(trc::location!())?
        {
            changes.push(mailbox_item(*document_id, archive.unarchive::<Mailbox>()?));
        }
    }

    Ok(apply_mailbox_changes(mailboxes, changed_ids, changes))
}

fn apply_mailbox_changes(
    mailboxes: &MailboxesCache,
    changed_ids: &AHashMap<u32, bool>,
    changes: Vec<MailboxCache>,
) -> MailboxesCache {
    if let Some(appended) = appended_mailboxes(mailboxes, changed_ids, &changes) {
        extend_mailbox_cache(mailboxes, changes, appended)
    } else {
        rebuild_mailbox_cache(mailboxes, changed_ids, changes)
    }
}

fn appended_mailboxes(
    mailboxes: &MailboxesCache,
    changed_ids: &AHashMap<u32, bool>,
    changes: &[MailboxCache],
) -> Option<usize> {
    let mut updated = 0;
    let mut new_ids = Vec::new();
    for item in changes {
        if let Some(current) = mailboxes.mailbox_by_id(&item.document_id) {
            if current.name != item.name
                || current.parent_id != item.parent_id
                || current.role != item.role
            {
                return None;
            }
            updated += 1;
        } else {
            new_ids.push(item.document_id);
        }
    }

    if changed_ids
        .keys()
        .filter(|id| mailboxes.has_mailbox_id(id))
        .count()
        != updated
    {
        return None;
    }

    if !new_ids.is_empty() {
        new_ids.sort_unstable();
        if mailboxes.items.iter().any(|item| {
            item.parent_id()
                .is_some_and(|parent_id| new_ids.binary_search(&parent_id).is_ok())
        }) {
            return None;
        }
    }

    Some(new_ids.len())
}

fn extend_mailbox_cache(
    mailboxes: &MailboxesCache,
    changes: Vec<MailboxCache>,
    appended: usize,
) -> MailboxesCache {
    let first_new = mailboxes.items.len();
    let mut cache = MailboxesCacheBuilder {
        items: Vec::with_capacity(first_new + appended),
        index: mailboxes.index.clone(),
        size: mailboxes.size,
        change_id: 0,
    };
    cache.items.extend_from_slice(&mailboxes.items);
    cache.index.reserve(appended);

    let mut topological_sort = TopologicalSort::with_capacity(appended);
    for mut item in changes {
        if let Some(idx) = cache.index.get(&item.document_id)
            && let Some(current) = cache.items.get_mut(*idx as usize)
        {
            item.name = current.name.clone();
            item.path = current.path.clone();
            *current = item;
        } else {
            let idx = cache.items.len();
            item.path = base_path(&item, idx);
            topological_sort.insert(sort_parent(&item), item.document_id + 1);
            cache.index.insert(item.document_id, idx as u32);
            cache.items.push(item);
        }
    }

    resolve_paths(&mut cache, topological_sort, first_new);
    cache.size += cache
        .items
        .get(first_new..)
        .unwrap_or_default()
        .iter()
        .map(item_size)
        .sum::<u64>();

    cache.build()
}

fn rebuild_mailbox_cache(
    mailboxes: &MailboxesCache,
    changed_ids: &AHashMap<u32, bool>,
    changes: Vec<MailboxCache>,
) -> MailboxesCache {
    let mut cache = MailboxesCacheBuilder {
        items: Vec::with_capacity(mailboxes.items.len()),
        index: AHashMap::with_capacity(mailboxes.items.len()),
        size: 0,
        change_id: 0,
    };

    for item in changes {
        mailbox_insert(&mut cache, item);
    }

    for item in mailboxes.items.iter() {
        if !changed_ids.contains_key(&item.document_id) {
            mailbox_insert(&mut cache, item.clone());
        }
    }

    build_tree(&mut cache);

    cache.build()
}

pub(crate) async fn full_mailbox_cache_build(
    server: &Server,
    account_id: u32,
    change_id: u64,
) -> trc::Result<MailboxesCache> {
    let mut cache = MailboxesCacheBuilder {
        items: Default::default(),
        index: Default::default(),
        size: 0,
        change_id,
    };

    server
        .archives(
            account_id,
            Collection::Mailbox,
            Field::ARCHIVE,
            &(),
            |document_id, archive| {
                insert_item(&mut cache, document_id, archive.unarchive::<Mailbox>()?);
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    if cache.items.is_empty() {
        server
            .create_system_folders(account_id)
            .await
            .caused_by(trc::location!())?;
        cache.change_id = server
            .core
            .storage
            .data
            .get_last_change_id(account_id, SyncCollection::Email.into())
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
        server
            .archives(
                account_id,
                Collection::Mailbox,
                Field::ARCHIVE,
                &(),
                |document_id, archive| {
                    insert_item(&mut cache, document_id, archive.unarchive::<Mailbox>()?);
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    build_tree(&mut cache);

    Ok(cache.build())
}

fn insert_item(cache: &mut MailboxesCacheBuilder, document_id: u32, mailbox: &ArchivedMailbox) {
    mailbox_insert(cache, mailbox_item(document_id, mailbox));
}

fn mailbox_item(document_id: u32, mailbox: &ArchivedMailbox) -> MailboxCache {
    let parent_id = mailbox.parent_id.to_native();
    let name: Arc<str> = mailbox.name.as_str().into();
    MailboxCache {
        document_id,
        path: name.clone(),
        name,
        role: mailbox.role(),
        parent_id: if parent_id > 0 {
            parent_id - 1
        } else {
            u32::MAX
        },
        sort_order: mailbox
            .sort_order
            .as_ref()
            .map(|s| s.to_native())
            .unwrap_or(u32::MAX),
        subscribers: mailbox.subscribers.iter().map(|s| s.to_native()).collect(),
        uid_validity: mailbox.uid_validity.to_native(),
        acls: mailbox
            .acls
            .iter()
            .map(|acl| AclGrant {
                account_id: acl.account_id.to_native(),
                grants: Bitmap::from(&acl.grants),
            })
            .collect(),
        metadata_kinds: mailbox.metadata_kinds(),
    }
}

fn build_tree(cache: &mut MailboxesCacheBuilder) {
    let mut topological_sort = TopologicalSort::with_capacity(cache.items.len());

    for (idx, mailbox) in cache.items.iter_mut().enumerate() {
        topological_sort.insert(sort_parent(mailbox), mailbox.document_id + 1);
        mailbox.path = base_path(mailbox, idx);
    }

    resolve_paths(cache, topological_sort, 0);

    cache.size = cache.items.iter().map(item_size).sum();
}

fn sort_parent(mailbox: &MailboxCache) -> u32 {
    if mailbox.parent_id == u32::MAX {
        0
    } else {
        mailbox.parent_id + 1
    }
}

fn base_path(mailbox: &MailboxCache, idx: usize) -> Arc<str> {
    if matches!(mailbox.role, SpecialUse::Inbox) {
        "INBOX".into()
    } else if mailbox.is_root() && mailbox.name.eq_ignore_ascii_case("inbox") {
        format!("INBOX {}", idx + 1).into()
    } else {
        mailbox.name.clone()
    }
}

fn resolve_paths(
    cache: &mut MailboxesCacheBuilder,
    topological_sort: TopologicalSort<u32>,
    first_idx: usize,
) {
    let mut path = String::new();
    for folder_id in topological_sort.into_iterator() {
        if let Some(folder_id) = folder_id.checked_sub(1)
            && let Some(idx) = cache.index.get(&folder_id).map(|idx| *idx as usize)
            && idx >= first_idx
            && let Some(folder) = cache.items.get(idx)
            && let Some(parent) = folder
                .parent_id()
                .and_then(|parent_id| by_id(cache, &parent_id))
        {
            path.clear();
            path.push_str(&parent.path);
            path.push('/');
            path.push_str(&folder.path);
            if let Some(folder) = cache.items.get_mut(idx) {
                folder.path = path.as_str().into();
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
pub(crate) fn mailboxes_cache_from(mailboxes: &[(u32, Mailbox)]) -> MailboxesCache {
    let mut cache = MailboxesCacheBuilder {
        items: Default::default(),
        index: Default::default(),
        size: 0,
        change_id: 0,
    };
    for (document_id, mailbox) in mailboxes {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(mailbox).expect("the mailbox archives");
        let archived = rkyv::access::<ArchivedMailbox, rkyv::rancor::Error>(&bytes)
            .expect("the archive validates");
        insert_item(&mut cache, *document_id, archived);
    }
    build_tree(&mut cache);
    cache.build()
}

impl MailboxesCacheBuilder {
    fn build(mut self) -> MailboxesCache {
        self.index.shrink_to_fit();
        MailboxesCache {
            change_id: self.change_id,
            index: self.index,
            items: self.items.into_boxed_slice(),
            size: self.size,
        }
    }
}

pub trait MailboxCacheAccess {
    fn mailbox_by_id(&self, id: &u32) -> Option<&MailboxCache>;
    fn mailbox_by_name(&self, name: &str) -> Option<&MailboxCache>;
    fn mailbox_by_path(&self, name: &str) -> Option<&MailboxCache>;
    fn mailbox_by_folded_path(&self, path: &str) -> Option<&MailboxCache>;
    fn mailbox_by_lowercase_path(&self, lowercase_path: &str) -> Option<&MailboxCache>;
    fn mailbox_by_role(&self, role: &SpecialUse) -> Option<&MailboxCache>;
    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;
    fn has_mailbox_id(&self, id: &u32) -> bool;
}

impl MailboxCacheAccess for MailboxesCache {
    fn mailbox_by_name(&self, name: &str) -> Option<&MailboxCache> {
        self.items
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }

    fn mailbox_by_path(&self, path: &str) -> Option<&MailboxCache> {
        self.items
            .iter()
            .find(|m| m.path.eq_ignore_ascii_case(path))
    }

    fn mailbox_by_folded_path(&self, path: &str) -> Option<&MailboxCache> {
        let mut folded_path = String::with_capacity(path.len());
        let mut found = None;
        for name in path.split('/').map(str::trim) {
            if !folded_path.is_empty() {
                folded_path.push('/');
            }
            folded_path.extend(name.chars().flat_map(char::to_lowercase));
            found = Some(self.mailbox_by_lowercase_path(&folded_path)?);
        }
        found
    }

    fn mailbox_by_lowercase_path(&self, lowercase_path: &str) -> Option<&MailboxCache> {
        self.items.iter().find(|m| {
            m.path
                .chars()
                .flat_map(char::to_lowercase)
                .eq(lowercase_path.chars())
        })
    }

    fn mailbox_by_role(&self, role: &SpecialUse) -> Option<&MailboxCache> {
        self.items.iter().find(|m| &m.role == role)
    }

    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        let check_acls = check_acls.into();

        RoaringBitmap::from_iter(
            self.items
                .iter()
                .filter(|m| {
                    m.acls
                        .as_slice()
                        .effective_acl(access_token)
                        .contains_all(check_acls)
                })
                .map(|m| m.document_id),
        )
    }

    fn mailbox_by_id(&self, id: &u32) -> Option<&MailboxCache> {
        self.index
            .get(id)
            .and_then(|idx| self.items.get(*idx as usize))
    }

    fn has_mailbox_id(&self, id: &u32) -> bool {
        self.index.contains_key(id)
    }
}

impl MailboxCacheAccess for MessageStoreCache {
    fn mailbox_by_id(&self, id: &u32) -> Option<&MailboxCache> {
        self.mailboxes.mailbox_by_id(id)
    }

    fn mailbox_by_name(&self, name: &str) -> Option<&MailboxCache> {
        self.mailboxes.mailbox_by_name(name)
    }

    fn mailbox_by_path(&self, path: &str) -> Option<&MailboxCache> {
        self.mailboxes.mailbox_by_path(path)
    }

    fn mailbox_by_folded_path(&self, path: &str) -> Option<&MailboxCache> {
        self.mailboxes.mailbox_by_folded_path(path)
    }

    fn mailbox_by_lowercase_path(&self, lowercase_path: &str) -> Option<&MailboxCache> {
        self.mailboxes.mailbox_by_lowercase_path(lowercase_path)
    }

    fn mailbox_by_role(&self, role: &SpecialUse) -> Option<&MailboxCache> {
        self.mailboxes.mailbox_by_role(role)
    }

    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        self.mailboxes.shared_mailboxes(access_token, check_acls)
    }

    fn has_mailbox_id(&self, id: &u32) -> bool {
        self.mailboxes.has_mailbox_id(id)
    }
}

#[inline(always)]
fn by_id<'x>(cache: &'x MailboxesCacheBuilder, id: &u32) -> Option<&'x MailboxCache> {
    cache
        .index
        .get(id)
        .and_then(|idx| cache.items.get(*idx as usize))
}

fn mailbox_insert(cache: &mut MailboxesCacheBuilder, item: MailboxCache) {
    let id = item.document_id;
    if let Some(idx) = cache.index.get(&id) {
        cache.items[*idx as usize] = item;
    } else {
        let idx = cache.items.len() as u32;
        cache.items.push(item);
        cache.index.insert(id, idx);
    }
}

fn item_size(item: &MailboxCache) -> u64 {
    let path_size = if Arc::ptr_eq(&item.name, &item.path) {
        0
    } else {
        shared_str_size(&item.path)
    };
    (size_of::<MailboxCache>() + shared_str_size(&item.name) + path_size) as u64
}

fn shared_str_size(value: &Arc<str>) -> usize {
    2 * size_of::<usize>() + value.len()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/cache/mailbox/tests.rs"]
mod tests;
