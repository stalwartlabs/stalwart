/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, cache::exchange_sessions::ExchangeSessionLimit};
use std::{any::Any, sync::Arc, time::Duration};

pub trait ExchangeSessionSlot: Sync + Send {
    fn exchange_session<T: Any + Send + Sync>(&self, account_id: u32, id: u128) -> Option<Arc<T>>;

    fn insert_exchange_session<T: Any + Send + Sync>(
        &self,
        account_id: u32,
        id: u128,
        value: Arc<T>,
        ttl: Duration,
    ) -> Result<(), ExchangeSessionLimit>;

    fn insert_exchange_session_evicting<T: Any + Send + Sync>(
        &self,
        account_id: u32,
        id: u128,
        value: Arc<T>,
        ttl: Duration,
    ) -> Result<(), ExchangeSessionLimit>;

    fn remove_exchange_session<T: Any + Send + Sync>(&self, account_id: u32, id: u128);
}

impl ExchangeSessionSlot for Server {
    fn exchange_session<T: Any + Send + Sync>(&self, account_id: u32, id: u128) -> Option<Arc<T>> {
        self.inner.data.exchange_sessions.get(account_id, id)
    }

    fn insert_exchange_session<T: Any + Send + Sync>(
        &self,
        account_id: u32,
        id: u128,
        value: Arc<T>,
        ttl: Duration,
    ) -> Result<(), ExchangeSessionLimit> {
        self.inner
            .data
            .exchange_sessions
            .insert(account_id, id, value, ttl)
    }

    fn insert_exchange_session_evicting<T: Any + Send + Sync>(
        &self,
        account_id: u32,
        id: u128,
        value: Arc<T>,
        ttl: Duration,
    ) -> Result<(), ExchangeSessionLimit> {
        self.inner
            .data
            .exchange_sessions
            .insert_evicting(account_id, id, value, ttl)
    }

    fn remove_exchange_session<T: Any + Send + Sync>(&self, account_id: u32, id: u128) {
        self.inner
            .data
            .exchange_sessions
            .remove::<T>(account_id, id);
    }
}
