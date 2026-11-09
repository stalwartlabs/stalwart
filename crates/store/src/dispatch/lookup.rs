/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, InMemoryStore, Store, U64_LEN, Value,
    backend::{http::lookup::HttpStoreGet, memory::StaticMemoryStore},
    write::now,
};
use registry::schema::structs::Rate;
use std::borrow::Cow;
use trc::AddContext;

pub struct KeyValue<T> {
    pub key: Vec<u8>,
    pub value: T,
    pub expires: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateWindow {
    pub index: u64,
    pub expires_in: u64,
}

impl RateWindow {
    pub fn new(rate: &Rate, now: u64) -> Self {
        let period = rate.period.as_secs().max(1);
        RateWindow {
            index: now / period,
            expires_in: period - now % period,
        }
    }

    pub fn bucket(&self, prefix: u8, key: &[u8]) -> Vec<u8> {
        let mut bucket = Vec::with_capacity(key.len() + U64_LEN + 1);
        bucket.push(prefix);
        bucket.extend_from_slice(key);
        bucket.extend_from_slice(&self.index.to_be_bytes());
        bucket
    }
}

impl InMemoryStore {
    pub async fn key_set(&self, kv: KeyValue<Vec<u8>>) -> trc::Result<()> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => store.key_set(kv.key, kv.value, kv.expires, now()),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_set(&kv.key, &kv.value, kv.expires).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.key_set(&kv.key, &kv.value, kv.expires).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_set(kv).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_incr(&self, kv: KeyValue<i64>) -> trc::Result<i64> {
        self.key_incr_at(kv, now()).await
    }

    async fn key_incr_at(&self, kv: KeyValue<i64>, now: u64) -> trc::Result<i64> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => store.key_incr(kv.key, kv.value, kv.expires, now),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_incr(&kv.key, kv.value, kv.expires).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.key_incr(&kv.key, kv.value, kv.expires).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_incr(kv).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => Ok(store.key_delete(key.into().as_bytes(), now())),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete(key.into().as_bytes()).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.key_delete(key.into().as_bytes()).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_delete(key).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => {
                store.key_delete(key.into().as_bytes(), now());
                Ok(())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store.key_delete(key.into().as_bytes()).await.map(|_| ())
            }
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.key_delete(key.into().as_bytes()).await.map(|_| ()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.counter_delete(key).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => {
                store.key_delete_prefix(prefix);
                Ok(())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete_prefix(prefix).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.key_delete_prefix(prefix).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_delete_prefix(prefix).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
        &self,
        key: impl Into<LookupKey<'_>>,
    ) -> trc::Result<Option<T>> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => store.key_get(key.into().as_bytes(), now()),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_get(key.into().as_bytes()).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.key_get(key.into().as_bytes()).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_get(key).await,
            // SPDX-SnippetEnd
            InMemoryStore::Static(store) => Ok(match store.as_ref() {
                StaticMemoryStore::Map(map) => map
                    .get(key.into().as_str())
                    .map(|value| T::from(value.clone())),
                StaticMemoryStore::Set(set) => {
                    if set.contains(key.into().as_str()) {
                        Some(T::from(Value::Bool(true)))
                    } else {
                        None
                    }
                }
            }),
            InMemoryStore::Http(store) => {
                Ok(store.get(key.into().as_str()).map(|value| T::from(value)))
            }
            InMemoryStore::Sql(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
        .caused_by(trc::location!())
    }

    pub async fn key_exists(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => Ok(store.key_exists(key.into().as_bytes(), now())),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_exists(key.into().as_bytes()).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.key_exists(key.into().as_bytes()).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_exists(key).await,
            // SPDX-SnippetEnd
            InMemoryStore::Static(store) => Ok(match store.as_ref() {
                StaticMemoryStore::Map(map) => map.get(key.into().as_str()).is_some(),
                StaticMemoryStore::Set(set) => set.contains(key.into().as_str()),
            }),
            InMemoryStore::Http(store) => Ok(store.contains(key.into().as_str())),
            InMemoryStore::Sql(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
        .caused_by(trc::location!())
    }

    pub async fn is_rate_allowed(
        &self,
        prefix: u8,
        key: &[u8],
        rate: &Rate,
    ) -> trc::Result<Option<u64>> {
        let now = now();
        let window = RateWindow::new(rate, now);

        let requests = self
            .key_incr_at(
                KeyValue::new(window.bucket(prefix, key), 1).expires(window.expires_in),
                now,
            )
            .await
            .caused_by(trc::location!())?;

        if requests <= rate.count as i64 {
            Ok(None)
        } else {
            Ok(Some(window.expires_in))
        }
    }

    pub async fn rate_reset(&self, prefix: u8, key: &[u8], rate: &Rate) -> trc::Result<()> {
        self.counter_delete(RateWindow::new(rate, now()).bucket(prefix, key))
            .await
    }

    pub async fn try_lock(&self, prefix: u8, key: &[u8], duration: u64) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => {
                store.try_lock(KeyValue::<()>::build_key(prefix, key), duration, now())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store
                    .try_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => {
                store
                    .try_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => {
                store
                    .try_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn renew_lock(&self, prefix: u8, key: &[u8], duration: u64) -> trc::Result<()> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        match self {
            InMemoryStore::Local(store) => {
                store.renew_lock(KeyValue::<()>::build_key(prefix, key), duration, now())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store
                    .renew_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => {
                store
                    .renew_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => {
                store
                    .renew_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn try_lease(
        &self,
        prefix: u8,
        key: &[u8],
        token: u64,
        duration: u64,
    ) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        let key = KeyValue::<()>::build_key(prefix, key);
        match self {
            InMemoryStore::Local(store) => store.try_lease(key, token, duration, now()),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.try_lease(&key, token, duration).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.try_lease(&key, token, duration).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.try_lease(&key, token, duration).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn renew_lease(
        &self,
        prefix: u8,
        key: &[u8],
        token: u64,
        duration: u64,
    ) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        let key = KeyValue::<()>::build_key(prefix, key);
        match self {
            InMemoryStore::Local(store) => Ok(store.renew_lease(&key, token, duration, now())),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.renew_lease(&key, token, duration).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.renew_lease(&key, token, duration).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.renew_lease(&key, token, duration).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn release_lease(&self, prefix: u8, key: &[u8], token: u64) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_in_memory(self).await;

        let key = KeyValue::<()>::build_key(prefix, key);
        match self {
            InMemoryStore::Local(store) => Ok(store.release_lease(key, token)),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.release_lease(&key, token).await,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(store) => store.release_lease(&key, token).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.release_lease(&key, token).await,
            // SPDX-SnippetEnd
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn remove_lock(&self, prefix: u8, key: &[u8]) -> trc::Result<()> {
        let key = KeyValue::<()>::build_key(prefix, key);

        #[cfg(feature = "keep")]
        if let InMemoryStore::Keep(store) = self {
            #[cfg(stalwart_tests)]
            crate::dispatch::StoreOps::count_in_memory(self).await;

            return store.remove_lock(&key).await.caused_by(trc::location!());
        }

        self.key_delete(key).await.map(|_| ())
    }

    pub fn is_sql(&self) -> bool {
        match self {
            InMemoryStore::Sql(store) => store.is_sql(),
            _ => false,
        }
    }

    pub fn is_redis(&self) -> bool {
        match self {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => true,
            _ => false,
        }
    }

    pub fn is_remote(&self) -> bool {
        match self {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => true,
            #[cfg(feature = "keep")]
            InMemoryStore::Keep(_) => true,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(_) => true,
            // SPDX-SnippetEnd
            _ => false,
        }
    }

    pub fn into_store(self) -> Option<Store> {
        match self {
            InMemoryStore::Sql(store) => Some(store),
            _ => None,
        }
    }
}

pub enum LookupKey<'x> {
    String(String),
    StringRef(&'x str),
    Bytes(Vec<u8>),
    BytesRef(&'x [u8]),
}

impl<'x> From<&'x str> for LookupKey<'x> {
    fn from(key: &'x str) -> Self {
        LookupKey::StringRef(key)
    }
}

impl<'x> From<&'x String> for LookupKey<'x> {
    fn from(key: &'x String) -> Self {
        LookupKey::StringRef(key.as_str())
    }
}

impl<'x> From<&'x [u8]> for LookupKey<'x> {
    fn from(key: &'x [u8]) -> Self {
        LookupKey::BytesRef(key)
    }
}

impl<'x> From<Cow<'x, str>> for LookupKey<'x> {
    fn from(key: Cow<'x, str>) -> Self {
        match key {
            Cow::Borrowed(key) => LookupKey::StringRef(key),
            Cow::Owned(key) => LookupKey::String(key),
        }
    }
}

impl From<String> for LookupKey<'static> {
    fn from(key: String) -> Self {
        LookupKey::String(key)
    }
}

impl From<Vec<u8>> for LookupKey<'static> {
    fn from(key: Vec<u8>) -> Self {
        LookupKey::Bytes(key)
    }
}

impl LookupKey<'_> {
    pub fn as_str(&self) -> &str {
        match self {
            LookupKey::String(string) => string,
            LookupKey::StringRef(string) => string,
            LookupKey::Bytes(bytes) => std::str::from_utf8(bytes).unwrap_or_default(),
            LookupKey::BytesRef(bytes) => std::str::from_utf8(bytes).unwrap_or_default(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            LookupKey::String(string) => string.as_bytes(),
            LookupKey::StringRef(string) => string.as_bytes(),
            LookupKey::Bytes(bytes) => bytes.as_slice(),
            LookupKey::BytesRef(bytes) => bytes,
        }
    }
}

impl<T> KeyValue<T> {
    pub fn build_key(prefix: u8, key: impl AsRef<[u8]>) -> Vec<u8> {
        let key_ = key.as_ref();
        let mut key = Vec::with_capacity(key_.len() + 1);
        key.push(prefix);
        key.extend_from_slice(key_);
        key
    }

    pub fn with_prefix(prefix: u8, key: impl AsRef<[u8]>, value: T) -> Self {
        Self {
            key: Self::build_key(prefix, key),
            value,
            expires: None,
        }
    }

    pub fn new(key: impl Into<Vec<u8>>, value: T) -> Self {
        Self {
            key: key.into(),
            value,
            expires: None,
        }
    }

    pub fn expires(mut self, expires: u64) -> Self {
        self.expires = expires.into();
        self
    }

    pub fn expires_opt(mut self, expires: Option<u64>) -> Self {
        self.expires = expires;
        self
    }
}

impl From<Value<'static>> for String {
    fn from(value: Value<'static>) -> Self {
        match value {
            Value::Text(string) => string.into_owned(),
            Value::Blob(bytes) => String::from_utf8_lossy(bytes.as_ref()).into_owned(),
            Value::Bool(boolean) => boolean.to_string(),
            Value::Null => String::new(),
            Value::Integer(num) => num.to_string(),
            Value::Float(num) => num.to_string(),
        }
    }
}
