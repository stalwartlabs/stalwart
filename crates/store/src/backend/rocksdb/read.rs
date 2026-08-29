/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RocksDbStore, into_error};
use crate::{
    Deserialize, IterateParams, Key, ValueKey, backend::rocksdb::CfHandle, write::ValueClass,
};
use rocksdb::ReadOptions;

impl RocksDbStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let db = self.db.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let cf = db.subspace_handle(subspace);
            db.get_pinned_cf(&cf, &key)
                .map_err(into_error)
                .and_then(|value| {
                    if let Some(value) = value {
                        U::deserialize_with_key(&key, &value).map(Some)
                    } else {
                        Ok(None)
                    }
                })
        })
        .await
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let db = self.db.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let cf = db.subspace_handle(subspace);
            db.get_pinned_cf(&cf, &key)
                .map_err(into_error)
                .map(|value| value.is_some())
        })
        .await
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let db = self.db.clone();

        self.block_worker(move || {
            let cf = db.subspace_handle(params.begin.subspace());
            let begin = params.begin.serialize(0);
            let end = params.end.serialize(0);
            let mut upper_bound = Vec::with_capacity(end.len() + 1);

            upper_bound.extend_from_slice(&end);
            upper_bound.push(0u8);

            let mut read_opts = ReadOptions::default();
            read_opts.set_iterate_lower_bound(begin.as_slice());
            read_opts.set_iterate_upper_bound(upper_bound);
            read_opts.set_auto_readahead_size(true);

            let mut it = db.raw_iterator_cf_opt(&cf, read_opts);
            if params.ascending {
                it.seek(&begin);
            } else {
                it.seek_for_prev(&end);
            }

            while it.valid() {
                let Some(key) = it.key() else {
                    break;
                };
                let value = if params.values {
                    it.value().unwrap_or_default()
                } else {
                    &[][..]
                };

                if !cb(key, value)? || params.first {
                    return Ok(());
                }

                if params.ascending {
                    it.next();
                } else {
                    it.prev();
                }
            }

            it.status().map_err(into_error)
        })
        .await
    }

    pub(crate) async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let db = self.db.clone();

        self.block_worker(move || {
            let cf = db.subspace_handle(ranges[0].begin.subspace());

            for params in &ranges {
                let begin = params.begin.serialize(0);
                let end = params.end.serialize(0);
                let mut upper_bound = Vec::with_capacity(end.len() + 1);

                upper_bound.extend_from_slice(&end);
                upper_bound.push(0u8);

                let mut read_opts = ReadOptions::default();
                read_opts.set_iterate_lower_bound(begin.as_slice());
                read_opts.set_iterate_upper_bound(upper_bound);
                read_opts.set_auto_readahead_size(true);

                let mut it = db.raw_iterator_cf_opt(&cf, read_opts);
                it.seek(&begin);

                while it.valid() {
                    let Some(key) = it.key() else {
                        break;
                    };
                    let value = if params.values {
                        it.value().unwrap_or_default()
                    } else {
                        &[][..]
                    };

                    if !cb(key, value)? {
                        return Ok(());
                    }

                    it.next();
                }

                it.status().map_err(into_error)?;
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let db = self.db.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let cf = db.subspace_handle(subspace);

            db.get_pinned_cf(&cf, &key)
                .map_err(into_error)
                .and_then(|bytes| {
                    Ok(if let Some(bytes) = bytes {
                        i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
                            trc::Error::corrupted_key(&key, (&bytes[..]).into(), trc::location!())
                        })?)
                    } else {
                        0
                    })
                })
        })
        .await
    }
}
