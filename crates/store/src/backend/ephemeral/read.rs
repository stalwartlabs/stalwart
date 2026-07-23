/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::EphemeralStore;
use crate::{Deserialize, IterateParams, Key, ValueKey, write::ValueClass};

impl EphemeralStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let subspace = key.subspace();
        let key_bytes = key.serialize(0);
        let state = self.state.read();
        match state
            .subspaces
            .get(&subspace)
            .and_then(|m| m.get(&key_bytes))
        {
            Some(value) => U::deserialize_with_key(&key_bytes, value).map(Some),
            None => Ok(None),
        }
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let subspace = key.subspace();
        let key_bytes = key.serialize(0);
        let state = self.state.read();
        Ok(state
            .subspaces
            .get(&subspace)
            .is_some_and(|m| m.contains_key(&key_bytes)))
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let subspace = params.begin.subspace();
        let begin = params.begin.serialize(0);
        let end = params.end.serialize(0);
        let state = self.state.read();
        let Some(map) = state.subspaces.get(&subspace) else {
            return Ok(());
        };

        if params.ascending {
            for (k, v) in map.range(begin..=end) {
                if !cb(k.as_slice(), v.as_slice())? || params.first {
                    break;
                }
            }
        } else {
            for (k, v) in map.range(begin..=end).rev() {
                if !cb(k.as_slice(), v.as_slice())? || params.first {
                    break;
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let subspace = key.subspace();
        let key_bytes = key.serialize(0);
        let state = self.state.read();
        match state
            .subspaces
            .get(&subspace)
            .and_then(|m| m.get(&key_bytes))
        {
            Some(bytes) => Ok(i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
                trc::Error::corrupted_key(&key_bytes, Some(bytes.as_slice()), trc::location!())
            })?)),
            None => Ok(0),
        }
    }
}
