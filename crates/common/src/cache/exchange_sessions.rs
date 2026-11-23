/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use parking_lot::Mutex;
use std::{
    any::{Any, TypeId},
    mem,
    sync::Arc,
    time::Duration,
};
use store::write::now;

pub const EXCHANGE_SESSIONS_MAX: usize = 16_384;
pub const EXCHANGE_SESSIONS_MAX_PER_KIND: usize = 32;
const SWEEP_INTERVAL: u64 = 60;

pub type ExchangeSessionValue = Arc<dyn Any + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeSessionLimit {
    Node,
    Account,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overflow {
    Refuse,
    EvictEarliest,
}

#[derive(Default)]
pub struct ExchangeSessions(Mutex<SessionTable>);

#[derive(Default)]
struct SessionTable {
    accounts: AHashMap<u32, Vec<SessionEntry>>,
    len: usize,
    swept_at: u64,
}

struct SessionEntry {
    id: u128,
    kind: TypeId,
    value: ExchangeSessionValue,
    expires: u64,
    ttl: u64,
}

impl ExchangeSessions {
    pub fn insert(
        &self,
        account_id: u32,
        id: u128,
        value: ExchangeSessionValue,
        ttl: Duration,
    ) -> Result<(), ExchangeSessionLimit> {
        let mut evicted = Vec::new();
        let result =
            self.0
                .lock()
                .insert(account_id, id, value, ttl_secs(ttl), now(), &mut evicted);
        drop(evicted);
        result
    }

    pub fn insert_evicting(
        &self,
        account_id: u32,
        id: u128,
        value: ExchangeSessionValue,
        ttl: Duration,
    ) -> Result<(), ExchangeSessionLimit> {
        let mut evicted = Vec::new();
        let result = self.0.lock().insert_evicting(
            account_id,
            id,
            value,
            ttl_secs(ttl),
            now(),
            &mut evicted,
        );
        drop(evicted);
        result
    }

    pub fn get<T: Any + Send + Sync>(&self, account_id: u32, id: u128) -> Option<Arc<T>> {
        let mut evicted = Vec::new();
        let result = self.0.lock().get(account_id, id, now(), &mut evicted);
        drop(evicted);
        result
    }

    pub fn remove<T: Any + Send + Sync>(
        &self,
        account_id: u32,
        id: u128,
    ) -> Option<ExchangeSessionValue> {
        self.0.lock().take(account_id, id, TypeId::of::<T>())
    }
}

impl SessionTable {
    fn insert(
        &mut self,
        account_id: u32,
        id: u128,
        value: ExchangeSessionValue,
        ttl: u64,
        now: u64,
        evicted: &mut Vec<ExchangeSessionValue>,
    ) -> Result<(), ExchangeSessionLimit> {
        let entry = SessionEntry::new(id, value, ttl, now);
        self.store(account_id, entry, now, Overflow::Refuse, evicted)
    }

    fn insert_evicting(
        &mut self,
        account_id: u32,
        id: u128,
        value: ExchangeSessionValue,
        ttl: u64,
        now: u64,
        evicted: &mut Vec<ExchangeSessionValue>,
    ) -> Result<(), ExchangeSessionLimit> {
        let entry = SessionEntry::new(id, value, ttl, now);
        self.store(account_id, entry, now, Overflow::EvictEarliest, evicted)
    }

    fn store(
        &mut self,
        account_id: u32,
        entry: SessionEntry,
        now: u64,
        overflow: Overflow,
        evicted: &mut Vec<ExchangeSessionValue>,
    ) -> Result<(), ExchangeSessionLimit> {
        let sweep_at = self.swept_at.saturating_add(SWEEP_INTERVAL);
        if now >= sweep_at || (self.len >= EXCHANGE_SESSIONS_MAX && now > self.swept_at) {
            self.sweep(now, evicted);
        }

        let (id, kind) = (entry.id, entry.kind);
        if let Some(entries) = self.accounts.get_mut(&account_id) {
            if let Some(existing) = entries
                .iter_mut()
                .find(|entry| entry.id == id && entry.kind == kind)
            {
                evicted.push(mem::replace(existing, entry).value);
                return Ok(());
            }
            if kind_count(entries, kind) >= EXCHANGE_SESSIONS_MAX_PER_KIND {
                let before = evicted.len();
                evicted.extend(
                    entries
                        .extract_if(.., |entry| entry.expires <= now)
                        .map(|entry| entry.value),
                );
                self.len -= evicted.len() - before;
                if kind_count(entries, kind) >= EXCHANGE_SESSIONS_MAX_PER_KIND {
                    let earliest = match overflow {
                        Overflow::Refuse => None,
                        Overflow::EvictEarliest => entries
                            .iter_mut()
                            .filter(|entry| entry.kind == kind)
                            .min_by_key(|entry| entry.expires),
                    };
                    let Some(earliest) = earliest else {
                        evicted.push(entry.value);
                        return Err(ExchangeSessionLimit::Account);
                    };
                    evicted.push(mem::replace(earliest, entry).value);
                    return Ok(());
                }
            }
        }
        if self.len >= EXCHANGE_SESSIONS_MAX {
            evicted.push(entry.value);
            return Err(ExchangeSessionLimit::Node);
        }

        self.accounts.entry(account_id).or_default().push(entry);
        self.len += 1;
        Ok(())
    }

    fn get<T: Any + Send + Sync>(
        &mut self,
        account_id: u32,
        id: u128,
        now: u64,
        evicted: &mut Vec<ExchangeSessionValue>,
    ) -> Option<Arc<T>> {
        let kind = TypeId::of::<T>();
        let entry = self
            .accounts
            .get_mut(&account_id)?
            .iter_mut()
            .find(|entry| entry.id == id && entry.kind == kind)?;
        if entry.expires > now {
            let value = entry.value.clone().downcast::<T>().ok()?;
            entry.expires = now.saturating_add(entry.ttl);
            return Some(value);
        }
        evicted.extend(self.take(account_id, id, kind));
        None
    }

    fn take(&mut self, account_id: u32, id: u128, kind: TypeId) -> Option<ExchangeSessionValue> {
        let entries = self.accounts.get_mut(&account_id)?;
        let position = entries
            .iter()
            .position(|entry| entry.id == id && entry.kind == kind)?;
        let entry = entries.swap_remove(position);
        if entries.is_empty() {
            self.accounts.remove(&account_id);
        }
        self.len -= 1;
        Some(entry.value)
    }

    fn sweep(&mut self, now: u64, evicted: &mut Vec<ExchangeSessionValue>) {
        let mut len = 0;
        self.accounts.retain(|_, entries| {
            evicted.extend(
                entries
                    .extract_if(.., |entry| entry.expires <= now)
                    .map(|entry| entry.value),
            );
            len += entries.len();
            !entries.is_empty()
        });
        self.len = len;
        self.swept_at = now;
    }
}

impl SessionEntry {
    fn new(id: u128, value: ExchangeSessionValue, ttl: u64, now: u64) -> Self {
        SessionEntry {
            id,
            kind: Any::type_id(value.as_ref()),
            value,
            expires: now.saturating_add(ttl),
            ttl,
        }
    }
}

fn ttl_secs(ttl: Duration) -> u64 {
    ttl.as_secs()
        .saturating_add(u64::from(ttl.subsec_nanos() > 0))
        .max(1)
}

fn kind_count(entries: &[SessionEntry], kind: TypeId) -> usize {
    entries.iter().filter(|entry| entry.kind == kind).count()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/cache/exchange_sessions/tests.rs"]
mod tests;
