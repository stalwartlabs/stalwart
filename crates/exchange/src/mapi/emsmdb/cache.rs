/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{execute::RopContext, state::Handle};
use crate::session::ExchangeSessionSlot;
use common::{
    Server,
    network::memory::{MemoryClass, MemoryReservation},
};
use exchange_proto::convert::model::MessageContent;
use std::{sync::Arc, time::Duration};

const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
pub const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CACHE_ENTRIES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageKey {
    pub mailbox_id: u32,
    pub message: u64,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKey {
    Message { mailbox_id: u32, message: u64 },
    Stream(u32),
}

enum EntryValue {
    Message {
        version: u64,
        change: Option<u64>,
        content: Arc<MessageContent>,
    },
    Stream(Arc<Vec<u8>>),
}

struct CacheEntry {
    key: EntryKey,
    value: EntryValue,
    size: u64,
    _reservation: MemoryReservation,
}

pub struct SessionContent {
    session: u128,
    entries: Vec<Arc<CacheEntry>>,
}

impl MessageKey {
    fn entry(self) -> EntryKey {
        EntryKey::Message {
            mailbox_id: self.mailbox_id,
            message: self.message,
        }
    }
}

impl SessionContent {
    fn find(&self, key: EntryKey) -> Option<&CacheEntry> {
        self.entries
            .iter()
            .map(Arc::as_ref)
            .find(|entry| entry.key == key)
    }

    fn with_entry(&self, entry: Option<CacheEntry>, drop_key: EntryKey) -> Option<Self> {
        let mut entries = Vec::with_capacity(MAX_CACHE_ENTRIES.saturating_add(1));
        entries.extend(
            self.entries
                .iter()
                .filter(|cached| cached.key != drop_key)
                .cloned(),
        );
        entries.extend(entry.map(Arc::new));
        let mut total = entries
            .iter()
            .fold(0u64, |total, entry| total.saturating_add(entry.size));
        let mut count = entries.len();
        entries.retain(|entry| {
            if (count <= MAX_CACHE_ENTRIES && total <= MAX_CACHE_BYTES)
                || matches!(entry.key, EntryKey::Stream(_))
            {
                return true;
            }
            total = total.saturating_sub(entry.size);
            count -= 1;
            false
        });
        (count <= MAX_CACHE_ENTRIES && total <= MAX_CACHE_BYTES).then_some(SessionContent {
            session: self.session,
            entries,
        })
    }
}

pub fn forget_session_content(server: &Server, account_id: u32, session: u128) {
    server.remove_exchange_session::<SessionContent>(account_id, session);
}

impl RopContext<'_, '_> {
    fn session_content(&self) -> Option<Arc<SessionContent>> {
        self.request
            .server
            .exchange_session::<SessionContent>(self.state.account_id, self.session)
            .filter(|content| content.session == self.session)
    }

    fn store_content(&self, entry: Option<CacheEntry>, drop_key: EntryKey) -> bool {
        let server = self.request.server;
        let next = match self.session_content() {
            Some(current) if entry.is_none() && current.find(drop_key).is_none() => return true,
            Some(current) => current.with_entry(entry, drop_key),
            None if entry.is_none() => return true,
            None => SessionContent {
                session: self.session,
                entries: Vec::new(),
            }
            .with_entry(entry, drop_key),
        };
        let Some(next) = next else {
            return false;
        };
        if next.entries.is_empty() {
            server.remove_exchange_session::<SessionContent>(self.state.account_id, self.session);
            true
        } else {
            server
                .insert_exchange_session(
                    self.state.account_id,
                    self.session,
                    Arc::new(next),
                    CACHE_TTL,
                )
                .is_ok()
        }
    }

    fn reserve(&self, size: u64) -> Option<MemoryReservation> {
        if size > MAX_CACHE_BYTES {
            return None;
        }
        let mut reservation = self.request.server.memory_reservation(MemoryClass::Read);
        reservation
            .try_reserve_within_limit(size)
            .ok()
            .map(|_| reservation)
    }

    pub fn cached_message(&self, key: MessageKey) -> Option<(Arc<MessageContent>, Option<u64>)> {
        match &self.session_content()?.find(key.entry())?.value {
            EntryValue::Message {
                version,
                change,
                content,
            } if *version == key.version => Some((content.clone(), *change)),
            _ => None,
        }
    }

    pub fn cache_message(
        &self,
        key: MessageKey,
        (content, change): (Arc<MessageContent>, Option<u64>),
        size: u64,
    ) {
        if let Some(reservation) = self.reserve(size) {
            self.store_content(
                Some(CacheEntry {
                    key: key.entry(),
                    value: EntryValue::Message {
                        version: key.version,
                        change,
                        content,
                    },
                    size,
                    _reservation: reservation,
                }),
                key.entry(),
            );
        }
    }

    pub fn cached_stream(&self, handle: Handle) -> Option<Arc<Vec<u8>>> {
        match &self
            .session_content()?
            .find(EntryKey::Stream(handle.0))?
            .value
        {
            EntryValue::Stream(bytes) => Some(bytes.clone()),
            EntryValue::Message { .. } => None,
        }
    }

    pub fn cache_stream(&self, handle: Handle, bytes: Arc<Vec<u8>>) -> bool {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let Some(reservation) = self.reserve(size) else {
            return false;
        };
        self.store_content(
            Some(CacheEntry {
                key: EntryKey::Stream(handle.0),
                value: EntryValue::Stream(bytes),
                size,
                _reservation: reservation,
            }),
            EntryKey::Stream(handle.0),
        )
    }

    pub fn forget_stream(&self, handle: Handle) {
        self.store_content(None, EntryKey::Stream(handle.0));
    }

    pub fn forget_content(&self) {
        forget_session_content(self.request.server, self.state.account_id, self.session);
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/cache/tests.rs"]
mod tests;
