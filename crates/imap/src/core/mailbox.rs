/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AccountCaches, AccountView, CounterDelta, Counters, MailboxCounters, MailboxId, MailboxName,
    MailboxRefresh, MailboxSync, Session, SessionData, UidNext,
};
use common::{
    MessageStoreCache, Server,
    auth::AccessToken,
    network::{SessionStream, limiter::InFlight},
    sharing::EffectiveAcl,
};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::INBOX_ID,
};
use parking_lot::Mutex;
use std::sync::atomic::Ordering;
use store::{ValueKey, roaring::RoaringBitmap, write::ValueClass};
use trc::AddContext;
use types::{acl::Acl, collection::Collection, special_use::SpecialUse};

impl<T: SessionStream> SessionData<T> {
    pub async fn new(
        session: &Session<T>,
        access_token: AccessToken,
        in_flight: Option<InFlight>,
    ) -> trc::Result<Self> {
        let data = SessionData {
            stream_tx: session.stream_tx.clone(),
            server: session.server.clone(),
            account_id: access_token.account_id(),
            session_id: session.session_id,
            mailboxes: Mutex::new(Vec::new()),
            state: access_token.state().into(),
            remote_addr: session.remote_addr,
            access_token,
            in_flight,
        };

        let shared = data
            .access_token
            .shared_accounts(Collection::Mailbox)
            .copied()
            .collect::<Vec<_>>();
        let mut accounts = Vec::with_capacity(shared.len() + 1);
        accounts.push(
            data.account_view(data.account_id, None, &data.access_token)
                .await
                .caused_by(trc::location!())?,
        );
        for account_id in shared {
            let prefix = data.shared_prefix(account_id).await?;
            accounts.push(
                data.account_view(account_id, Some(prefix), &data.access_token)
                    .await
                    .caused_by(trc::location!())?,
            );
        }
        *data.mailboxes.lock() = accounts;

        Ok(data)
    }

    async fn shared_prefix(&self, account_id: u32) -> trc::Result<String> {
        Ok(format!(
            "{}/{}",
            self.server.core.email.shared_folder,
            self.server
                .account(account_id)
                .await
                .caused_by(trc::location!())?
                .name()
        ))
    }

    async fn account_view(
        &self,
        account_id: u32,
        prefix: Option<String>,
        access_token: &AccessToken,
    ) -> trc::Result<AccountView> {
        let cache = self
            .server
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        Ok(AccountView::build(
            &self.server,
            &cache,
            account_id,
            prefix,
            access_token,
        ))
    }

    pub async fn synchronize_mailboxes(&self, return_changes: bool) -> trc::Result<MailboxRefresh> {
        self.synchronize_mailboxes_using(return_changes, AccountCaches::default())
            .await
    }

    pub async fn synchronize_mailboxes_using(
        &self,
        return_changes: bool,
        mut caches: AccountCaches,
    ) -> trc::Result<MailboxRefresh> {
        let mut changes = return_changes.then(MailboxSync::default);

        let access_token = self
            .refresh_access_token()
            .await
            .caused_by(trc::location!())?;
        let state = access_token.state();

        if self.state.load(Ordering::Relaxed) != state {
            let added_account_ids = {
                let mut accounts = self.mailboxes.lock();
                let has_access_to = access_token
                    .shared_accounts(Collection::Mailbox)
                    .copied()
                    .collect::<Vec<_>>();
                accounts.retain(|account| {
                    let keep = access_token.is_account_id(account.account_id)
                        || has_access_to.contains(&account.account_id);
                    if !keep && let Some(changes) = &mut changes {
                        changes
                            .deleted
                            .extend(account.names.iter().map(|entry| entry.name.clone()));
                    }
                    keep
                });
                has_access_to
                    .iter()
                    .copied()
                    .filter(|account_id| {
                        !accounts
                            .iter()
                            .skip(1)
                            .any(|account| account.account_id == *account_id)
                    })
                    .collect::<Vec<_>>()
            };

            for account_id in added_account_ids {
                let prefix = self.shared_prefix(account_id).await?;
                let account = self
                    .account_view(account_id, Some(prefix), &access_token)
                    .await?;
                if let Some(changes) = &mut changes {
                    changes
                        .added
                        .extend(account.names.iter().map(|entry| entry.name.clone()));
                }
                self.mailboxes.lock().push(account);
            }

            self.state.store(state, Ordering::Relaxed);
        }

        let account_states = self
            .mailboxes
            .lock()
            .iter()
            .map(|account| (account.account_id, account.mailboxes.change_id))
            .collect::<Vec<_>>();

        for (account_id, container_change_id) in account_states {
            let cache = caches.fetch(&self.server, account_id).await?;
            if cache.mailboxes.change_id != container_change_id
                && !self.refresh_account_structure(account_id, &cache, &access_token, &mut changes)
            {
                continue;
            }

            if let Some(changes) = &mut changes {
                let mut accounts = self.mailboxes.lock();
                if let Some(account) = accounts
                    .iter_mut()
                    .find(|account| account.account_id == account_id)
                    && let Some(previous) = account.refresh_counters(&cache)
                {
                    for entry in account
                        .names
                        .iter()
                        .filter(|entry| !changes.added.contains(&entry.name))
                    {
                        let before = previous
                            .get(entry.mailbox_id as usize)
                            .copied()
                            .unwrap_or_default();
                        let after = account.counters_of(entry.mailbox_id);
                        if before.total != after.total || before.unseen != after.unseen {
                            changes.changed.push(entry.name.clone());
                        }
                    }
                }
            }
        }

        Ok(MailboxRefresh { changes, caches })
    }

    fn refresh_account_structure(
        &self,
        account_id: u32,
        cache: &MessageStoreCache,
        access_token: &AccessToken,
        changes: &mut Option<MailboxSync>,
    ) -> bool {
        let mut accounts = self.mailboxes.lock();
        let Some(account) = accounts
            .iter_mut()
            .find(|account| account.account_id == account_id)
        else {
            return false;
        };

        let prefix = account.prefix.take();
        let refreshed = AccountView::build(&self.server, cache, account_id, prefix, access_token);
        if let Some(changes) = changes {
            for entry in &refreshed.names {
                if account.id_by_name(&entry.name).is_none() {
                    changes.added.push(entry.name.clone());
                }
            }
            for entry in &account.names {
                if refreshed.id_by_name(&entry.name).is_none() {
                    changes.deleted.push(entry.name.clone());
                }
            }
        }
        account.mailboxes = refreshed.mailboxes;
        account.visible = refreshed.visible;
        account.names = refreshed.names;
        account.parents = refreshed.parents;
        account.prefix = refreshed.prefix;
        true
    }

    pub fn ensure_counters(&self, account_id: u32, cache: &MessageStoreCache) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
        {
            account.ensure_counters(cache);
        }
    }

    pub fn has_counters_at(&self, account_id: u32, change_id: u64) -> bool {
        self.mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == account_id)
            .and_then(|account| account.counters.as_ref())
            .is_some_and(|counters| counters.change_id == change_id)
    }

    pub fn take_previous_counters(&self, account_id: u32) -> Option<Vec<Counters>> {
        self.mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
            .and_then(|account| account.previous_counters.take())
    }

    pub fn apply_counter_deltas(
        &self,
        account_id: u32,
        from_change_id: u64,
        to_change_id: u64,
        deltas: &[CounterDelta],
        rebuilt: bool,
    ) {
        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == account_id)
        {
            account.apply_counter_deltas(from_change_id, to_change_id, deltas, rebuilt);
        }
    }

    pub async fn seed_mailbox_counters(&self) -> trc::Result<()> {
        let account_ids = self
            .mailboxes
            .lock()
            .iter()
            .map(|account| account.account_id)
            .collect::<Vec<_>>();
        for account_id in account_ids {
            let cache = self
                .server
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;
            if let Some(account) = self
                .mailboxes
                .lock()
                .iter_mut()
                .find(|account| account.account_id == account_id)
            {
                account.ensure_counters(&cache);
                account.previous_counters = None;
            }
        }
        Ok(())
    }

    pub fn get_mailbox_by_name(&self, mailbox_name: &str) -> Option<MailboxId> {
        let is_inbox = mailbox_name.eq_ignore_ascii_case("inbox");
        for account in self.mailboxes.lock().iter() {
            if account
                .prefix
                .as_ref()
                .is_none_or(|prefix| mailbox_name.starts_with(prefix.as_str()))
            {
                let mailbox_id = if is_inbox {
                    account.has_mailbox_id(INBOX_ID).then_some(INBOX_ID)
                } else {
                    account.id_by_name(mailbox_name)
                };
                if let Some(mailbox_id) = mailbox_id {
                    return MailboxId {
                        account_id: account.account_id,
                        mailbox_id,
                    }
                    .into();
                }
            }
        }
        None
    }

    pub fn get_mailbox_by_id(&self, account_id: u32, mailbox_id: u32) -> Option<MailboxId> {
        self.mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == account_id)
            .filter(|account| account.has_mailbox_id(mailbox_id))
            .map(|_| MailboxId {
                account_id,
                mailbox_id,
            })
    }

    pub fn uid_validity(&self, mailbox: &MailboxId) -> u32 {
        self.mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == mailbox.account_id)
            .map_or(0, |account| account.uid_validity(mailbox.mailbox_id))
    }

    pub async fn uid_next(
        &self,
        cache: &MessageStoreCache,
        mailbox: &MailboxId,
    ) -> trc::Result<u32> {
        let change_id = cache.emails.change_id;
        if let Some(value) = self
            .mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == mailbox.account_id)
            .and_then(|account| account.cached_uid_next(mailbox.mailbox_id, change_id))
        {
            return Ok(value);
        }

        let value = self
            .server
            .core
            .storage
            .data
            .get_counter(ValueKey {
                account_id: mailbox.account_id,
                collection: Collection::Mailbox.into(),
                document_id: mailbox.mailbox_id,
                class: ValueClass::MailboxUid,
            })
            .await
            .caused_by(trc::location!())
            .map(|v| (v + 1) as u32)?;

        if let Some(account) = self
            .mailboxes
            .lock()
            .iter_mut()
            .find(|account| account.account_id == mailbox.account_id)
        {
            account.remember_uid_next(UidNext {
                mailbox_id: mailbox.mailbox_id,
                change_id,
                value,
            });
        }

        Ok(value)
    }

    pub async fn check_mailbox_acl(
        &self,
        cache: Option<&MessageStoreCache>,
        account_id: u32,
        mailbox_id: u32,
        item: Acl,
    ) -> trc::Result<bool> {
        let access_token = self.refresh_access_token().await?;
        if access_token.is_member(account_id) {
            return Ok(true);
        }
        let fetched;
        let cache = match cache {
            Some(cache) => cache,
            None => {
                fetched = self
                    .server
                    .get_cached_messages(account_id)
                    .await
                    .caused_by(trc::location!())?;
                &fetched
            }
        };
        cache
            .mailbox_by_id(&mailbox_id)
            .map(|mailbox| {
                mailbox
                    .acls
                    .as_slice()
                    .effective_acl(&access_token)
                    .contains(item)
            })
            .ok_or_else(|| {
                trc::ImapEvent::Error
                    .caused_by(trc::location!())
                    .details("Mailbox no longer exists.")
            })
    }
}

impl AccountView {
    pub fn build(
        server: &Server,
        cache: &MessageStoreCache,
        account_id: u32,
        prefix: Option<String>,
        access_token: &AccessToken,
    ) -> Self {
        let visible = if access_token.is_member(account_id) {
            None
        } else {
            Some(cache.shared_mailboxes(access_token, Acl::Read))
        };
        let is_visible = |mailbox_id: u32| {
            visible
                .as_ref()
                .is_none_or(|visible| visible.contains(mailbox_id))
        };

        let mut parents = RoaringBitmap::new();
        let mut special_uses = Vec::new();
        for mailbox in cache.mailboxes.items.iter() {
            if let Some(parent_id) = mailbox.parent_id() {
                parents.insert(parent_id);
            }
            if !matches!(mailbox.role, SpecialUse::None) && is_visible(mailbox.document_id) {
                special_uses.push((mailbox.role, mailbox.document_id));
            }
        }

        let mut names = Vec::with_capacity(cache.mailboxes.items.len());
        for mailbox in cache
            .mailboxes
            .items
            .iter()
            .filter(|mailbox| is_visible(mailbox.document_id))
        {
            let name = match &prefix {
                Some(prefix) => {
                    let mut name = String::with_capacity(prefix.len() + mailbox.path.len() + 1);
                    name.push_str(prefix);
                    name.push('/');
                    name.push_str(&mailbox.path);
                    name
                }
                None => mailbox.path.clone(),
            };
            let mailbox_id = server
                .core
                .email
                .default_folders
                .iter()
                .find(|folder| {
                    folder.name == name || folder.aliases.iter().any(|alias| alias == &name)
                })
                .and_then(|folder| {
                    special_uses
                        .iter()
                        .find(|(role, _)| *role == folder.special_use)
                        .map(|(_, mailbox_id)| *mailbox_id)
                })
                .unwrap_or(mailbox.document_id);
            names.push(MailboxName { name, mailbox_id });
        }
        names.sort_unstable_by(|a, b| a.name.cmp(&b.name));

        AccountView {
            account_id,
            prefix,
            mailboxes: cache.mailboxes.clone(),
            visible,
            names,
            parents,
            counters: None,
            previous_counters: None,
            uid_next: Vec::new(),
        }
    }

    pub fn ensure_counters(&mut self, cache: &MessageStoreCache) {
        if let Some(stale) = self
            .counters
            .take_if(|counters| counters.change_id != cache.emails.change_id)
        {
            self.previous_counters.get_or_insert(stale.by_mailbox);
        }
        if self.counters.is_none() {
            self.counters = Some(MailboxCounters::compute(cache));
        }
    }

    pub fn refresh_counters(&mut self, cache: &MessageStoreCache) -> Option<Vec<Counters>> {
        self.ensure_counters(cache);
        self.previous_counters.take()
    }

    pub fn apply_counter_deltas(
        &mut self,
        from_change_id: u64,
        to_change_id: u64,
        deltas: &[CounterDelta],
        rebuilt: bool,
    ) {
        match &mut self.counters {
            Some(counters) if !rebuilt && counters.change_id == from_change_id => {
                if self.previous_counters.is_none() {
                    self.previous_counters = Some(counters.by_mailbox.clone());
                }
                counters.apply_deltas(deltas, to_change_id);
            }
            Some(counters) if counters.change_id == to_change_id => {}
            Some(counters) => {
                if self.previous_counters.is_none() {
                    self.previous_counters = Some(std::mem::take(&mut counters.by_mailbox));
                }
                self.counters = None;
            }
            None => {}
        }
    }
}
