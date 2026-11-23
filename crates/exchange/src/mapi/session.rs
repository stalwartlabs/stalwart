/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{KV_EXCHANGE_SESSION, KV_LOCK_EXCHANGE_SESSION, Server};
use exchange_proto::mapi::http::EXPIRATION_MS;
use registry::schema::{prelude::Duration, structs::Rate};
use std::time::Duration as StdDuration;
use store::{
    Deserialize, Value,
    dispatch::lookup::{KeyValue, RateWindow},
    rand,
    write::{Archive, ArchiveBytes, now},
};
use trc::AddContext;

pub const SESSION_TTL_SECS: u64 = EXPIRATION_MS as u64 / 1000 + 60;
pub const SESSION_LOCK_SECS: u64 = 300;

const KEY_LEN: usize = 21;
const RATE_MARKER: u8 = 0xFF;
const LOCK_ATTEMPTS: usize = 5;
const LOCK_RETRY_DELAY: StdDuration = StdDuration::from_millis(20);
pub const CONNECT_RATE: Rate = Rate {
    count: 256,
    period: Duration(StdDuration::from_secs(SESSION_TTL_SECS)),
};
const COOKIE_LEN: usize = 42;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionKind {
    Emsmdb = 0,
    Nspi = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub kind: SessionKind,
    pub account_id: u32,
    pub id: u128,
}

impl SessionKey {
    pub fn generate(kind: SessionKind, account_id: u32) -> Self {
        SessionKey {
            kind,
            account_id,
            id: rand::random::<u128>(),
        }
    }

    pub fn parse(kind: SessionKind, value: &str) -> Option<Self> {
        if value.len() != COOKIE_LEN {
            return None;
        }
        let (prefix, rest) = value.split_at_checked(2)?;
        let (account, id) = rest.split_at_checked(8)?;
        let parsed_kind = u8::from_str_radix(prefix, 16).ok()?;
        if parsed_kind != kind as u8 {
            return None;
        }
        Some(SessionKey {
            kind,
            account_id: u32::from_str_radix(account, 16).ok()?,
            id: u128::from_str_radix(id, 16).ok()?,
        })
    }

    pub fn to_cookie(self) -> String {
        format!(
            "{:02x}{:08x}{:032x}",
            self.kind as u8, self.account_id, self.id
        )
    }

    fn key_bytes(self) -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        let (kind, rest) = key.split_at_mut(1);
        kind.fill(self.kind as u8);
        let (account, id) = rest.split_at_mut(4);
        account.copy_from_slice(&self.account_id.to_be_bytes());
        id.copy_from_slice(&self.id.to_be_bytes());
        key
    }
}

pub trait SessionState: Sized {
    fn encode(self) -> trc::Result<Vec<u8>>;
    fn decode(archive: &Archive<ArchiveBytes>) -> trc::Result<Self>;
}

pub enum LockOutcome {
    Acquired(SessionLock),
    Busy,
}

#[derive(Debug, Default)]
struct RawSession(Vec<u8>);

impl Deserialize for RawSession {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(RawSession(bytes.to_vec()))
    }
}

impl From<Value<'static>> for RawSession {
    fn from(value: Value<'static>) -> Self {
        match value {
            Value::Blob(bytes) => RawSession(bytes.into_owned()),
            _ => RawSession::default(),
        }
    }
}

fn session_key(key: SessionKey) -> Vec<u8> {
    KeyValue::<()>::build_key(KV_EXCHANGE_SESSION, key.key_bytes())
}

async fn load_raw(server: &Server, key: SessionKey) -> trc::Result<Option<RawSession>> {
    server
        .in_memory_store()
        .key_get::<RawSession>(session_key(key))
        .await
        .caused_by(trc::location!())
}

pub async fn load_archive(
    server: &Server,
    key: SessionKey,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .in_memory_store()
        .key_get::<Archive<ArchiveBytes>>(session_key(key))
        .await
        .caused_by(trc::location!())
}

pub async fn load_session<S: SessionState>(
    server: &Server,
    key: SessionKey,
) -> trc::Result<Option<S>> {
    load_archive(server, key)
        .await?
        .map(|archive| S::decode(&archive))
        .transpose()
}

pub async fn save_session<S: SessionState>(
    server: &Server,
    key: SessionKey,
    state: S,
) -> trc::Result<()> {
    save_encoded(server, key, state.encode()?).await
}

pub async fn session_exists(server: &Server, key: SessionKey) -> trc::Result<bool> {
    server
        .in_memory_store()
        .key_exists(session_key(key))
        .await
        .caused_by(trc::location!())
}

pub async fn refresh_session(server: &Server, key: SessionKey) -> trc::Result<bool> {
    match load_raw(server, key).await? {
        Some(raw) => save_encoded(server, key, raw.0).await.map(|_| true),
        None => Ok(false),
    }
}

async fn save_encoded(server: &Server, key: SessionKey, value: Vec<u8>) -> trc::Result<()> {
    server
        .in_memory_store()
        .key_set(
            KeyValue::with_prefix(KV_EXCHANGE_SESSION, key.key_bytes(), value)
                .expires(SESSION_TTL_SECS),
        )
        .await
        .caused_by(trc::location!())
}

fn connect_rate_key(account_id: u32) -> [u8; 5] {
    let mut key = [RATE_MARKER; 5];
    if let Some(account) = key.first_chunk_mut::<4>() {
        *account = account_id.to_be_bytes();
    }
    key
}

pub async fn connect_allowed(server: &Server, account_id: u32) -> trc::Result<bool> {
    server
        .in_memory_store()
        .is_rate_allowed(
            KV_EXCHANGE_SESSION,
            &connect_rate_key(account_id),
            &CONNECT_RATE,
        )
        .await
        .map(|retry| retry.is_none())
        .caused_by(trc::location!())
}

pub async fn delete_session(lock: &SessionLock) -> trc::Result<()> {
    let key = lock.key;
    let store = lock.server.in_memory_store();
    if !store
        .key_delete(session_key(key))
        .await
        .caused_by(trc::location!())?
    {
        return Ok(());
    }
    let window = RateWindow::new(&CONNECT_RATE, now());
    store
        .key_incr(
            KeyValue::new(
                window.bucket(KV_EXCHANGE_SESSION, &connect_rate_key(key.account_id)),
                -1,
            )
            .expires(window.expires_in),
        )
        .await
        .map(|_| ())
        .caused_by(trc::location!())
}

pub struct SessionLock {
    server: Server,
    key: SessionKey,
    held: bool,
}

impl SessionLock {
    pub async fn acquire(server: &Server, key: SessionKey) -> trc::Result<LockOutcome> {
        let acquired = server
            .in_memory_store()
            .try_lock(
                KV_LOCK_EXCHANGE_SESSION,
                &key.key_bytes(),
                SESSION_LOCK_SECS,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(if acquired {
            LockOutcome::Acquired(SessionLock {
                server: server.clone(),
                key,
                held: true,
            })
        } else {
            LockOutcome::Busy
        })
    }

    pub async fn acquire_patiently(server: &Server, key: SessionKey) -> trc::Result<LockOutcome> {
        for _ in 1..LOCK_ATTEMPTS {
            if let LockOutcome::Acquired(lock) = Self::acquire(server, key).await? {
                return Ok(LockOutcome::Acquired(lock));
            }
            tokio::time::sleep(LOCK_RETRY_DELAY).await;
        }
        Self::acquire(server, key).await
    }

    pub async fn release(mut self) -> trc::Result<()> {
        let result = unlock_session(&self.server, self.key).await;
        self.held = false;
        result
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        if self.held {
            let server = self.server.clone();
            let key = self.key;
            tokio::spawn(async move {
                if let Err(err) = unlock_session(&server, key).await {
                    trc::error!(err.details("Failed to release MAPI session lock"));
                }
            });
        }
    }
}

async fn unlock_session(server: &Server, key: SessionKey) -> trc::Result<()> {
    server
        .in_memory_store()
        .remove_lock(KV_LOCK_EXCHANGE_SESSION, &key.key_bytes())
        .await
        .caused_by(trc::location!())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/mapi/session/tests.rs"]
mod tests;
