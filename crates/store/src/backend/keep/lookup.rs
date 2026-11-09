/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{KeepKey, KeepStore, into_error, optional_ttl, ttl};
use crate::Deserialize;

impl KeepStore {
    pub async fn key_set(&self, key: &[u8], value: &[u8], expires: Option<u64>) -> trc::Result<()> {
        self.client
            .set(KeepKey::new(key).as_bytes(), value, optional_ttl(expires)?)
            .await
            .map_err(into_error)
    }

    pub async fn key_incr(&self, key: &[u8], value: i64, expires: Option<u64>) -> trc::Result<i64> {
        self.client
            .incr(KeepKey::new(key).as_bytes(), value, optional_ttl(expires)?)
            .await
            .map_err(into_error)
    }

    pub async fn try_lock(&self, key: &[u8], expires: u64) -> trc::Result<bool> {
        self.client
            .try_lock(KeepKey::new(key).as_bytes(), ttl(expires)?)
            .await
            .map_err(into_error)
    }

    pub async fn renew_lock(&self, key: &[u8], expires: u64) -> trc::Result<()> {
        self.client
            .renew_lock(KeepKey::new(key).as_bytes(), ttl(expires)?)
            .await
            .map_err(into_error)
    }

    pub async fn remove_lock(&self, key: &[u8]) -> trc::Result<()> {
        self.client
            .remove_lock(KeepKey::new(key).as_bytes())
            .await
            .map_err(into_error)
    }

    pub async fn try_lease(&self, key: &[u8], token: u64, expires: u64) -> trc::Result<bool> {
        self.client
            .try_lease(KeepKey::new(key).as_bytes(), token, ttl(expires)?)
            .await
            .map_err(into_error)
    }

    pub async fn renew_lease(&self, key: &[u8], token: u64, expires: u64) -> trc::Result<bool> {
        self.client
            .renew_lease(KeepKey::new(key).as_bytes(), token, ttl(expires)?)
            .await
            .map_err(into_error)
    }

    pub async fn release_lease(&self, key: &[u8], token: u64) -> trc::Result<bool> {
        self.client
            .release_lease(KeepKey::new(key).as_bytes(), token)
            .await
            .map_err(into_error)
    }

    pub async fn key_delete(&self, key: &[u8]) -> trc::Result<bool> {
        self.client
            .delete(KeepKey::new(key).as_bytes())
            .await
            .map_err(into_error)
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        self.client.delete_prefix(prefix).await.map_err(into_error)
    }

    pub async fn key_get<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        key: &[u8],
    ) -> trc::Result<Option<T>> {
        self.client
            .get(KeepKey::new(key).as_bytes())
            .await
            .map_err(into_error)?
            .map(T::deserialize_owned)
            .transpose()
    }

    pub async fn key_exists(&self, key: &[u8]) -> trc::Result<bool> {
        self.client
            .exists(KeepKey::new(key).as_bytes())
            .await
            .map_err(into_error)
    }
}
