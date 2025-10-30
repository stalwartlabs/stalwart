/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RocksDbStore, into_error};
use crate::{
    Deserialize, IterateParams, Key, ValueKey, backend::rocksdb::CfHandle, write::ValueClass,
};
use rocksdb::{Direction, IteratorMode};

impl RocksDbStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.get_pinned_cf(
                &db.cf_handle(std::str::from_utf8(&[key.subspace()]).unwrap())
                    .unwrap(),
                key.serialize(0),
            )
            .map_err(into_error)
            .and_then(|value| {
                if let Some(value) = value {
                    U::deserialize(&value).map(Some)
                } else {
                    Ok(None)
                }
            })
        })
        .await
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let db = self.db.clone();

        self.spawn_worker(move || {
            let cf = db.subspace_handle(params.begin.subspace());
            let begin = params.begin.serialize(0);
            let end = params.end.serialize(0);
            let it_mode = if params.ascending {
                IteratorMode::From(&begin, Direction::Forward)
            } else {
                IteratorMode::From(&end, Direction::Reverse)
            };

            for row in db.iterator_cf(&cf, it_mode) {
                let (key, value) = row.map_err(into_error)?;
                if key.as_ref() < begin.as_slice()
                    || key.as_ref() > end.as_slice()
                    || !cb(&key, &value)?
                    || params.first
                {
                    break;
                }
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
        self.spawn_worker(move || {
            let cf = self.db.subspace_handle(key.subspace());
            let key = key.serialize(0);

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
