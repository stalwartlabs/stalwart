/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FdbStore, MAX_READ_VERSION_AGE, MAX_VALUE_SIZE, REFRESH_READ_VERSION_AFTER, into_error,
};
use crate::{
    Deserialize, IterateParams, Key, ValueKey, WITH_SUBSPACE,
    backend::deserialize_i64_le,
    write::{MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, ValueClass, key::KeySerializer},
};
use foundationdb::{
    FdbError, KeySelector, RangeOption, Transaction,
    future::FdbSlice,
    options::{self},
};
use futures::TryStreamExt;
use std::time::Instant;

#[allow(dead_code)]
pub(crate) enum ChunkedValue {
    Single(FdbSlice),
    Chunked { n_chunks: u8, bytes: Vec<u8> },
    None,
}

struct ChunkedValueCollector {
    key: Vec<u8>,
    bytes: Vec<u8>,
}

impl FdbStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();

        loop {
            let trx = self.read_trx().await?;

            match read_chunked_value(&key, &trx, true).await {
                Ok(ChunkedValue::Single(bytes)) => {
                    return U::deserialize_with_key(key.get(1..).unwrap_or_default(), &bytes)
                        .map(Some);
                }
                Ok(ChunkedValue::Chunked { bytes, .. }) => {
                    return U::deserialize_owned_with_key(key.get(1..).unwrap_or_default(), bytes)
                        .map(Some);
                }
                Ok(ChunkedValue::None) => return Ok(None),
                Err(err) => {
                    self.on_read_error(trx, err, &mut retry_count, start)
                        .await?;
                }
            }
        }
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let key = key.serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();

        loop {
            let trx = self.read_trx().await?;

            match read_chunked_value(&key, &trx, true).await {
                Ok(ChunkedValue::Single(_) | ChunkedValue::Chunked { .. }) => return Ok(true),
                Ok(ChunkedValue::None) => return Ok(false),
                Err(err) => {
                    self.on_read_error(trx, err, &mut retry_count, start)
                        .await?;
                }
            }
        }
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let begin = params.begin.serialize(WITH_SUBSPACE);
        let end = params.end.serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();

        if !params.first {
            let mut last_key = vec![];
            let mut chunked_key: Option<ChunkedValueCollector> = None;

            'outer: loop {
                let begin_selector = if last_key.is_empty() {
                    KeySelector::first_greater_or_equal(&begin)
                } else {
                    KeySelector::first_greater_than(&last_key)
                };

                let trx = self.read_trx().await?;
                let mut values = trx.get_ranges(
                    RangeOption {
                        begin: begin_selector,
                        end: KeySelector::first_greater_than(&end),
                        mode: options::StreamingMode::WantAll,
                        reverse: !params.ascending,
                        ..Default::default()
                    },
                    true,
                );

                let mut last_key_ = vec![];
                loop {
                    match values.try_next().await {
                        Ok(Some(values)) => {
                            let mut key = &[] as &[u8];
                            for value in values.iter() {
                                key = value.key();

                                // Check whether we are collecting a chunked value
                                let cb_key = key.get(1..).unwrap_or_default();
                                let cb_value = value.value();

                                if let Some(chunk) = &mut chunked_key {
                                    if chunk.key.len() + 1 == cb_key.len()
                                        && cb_key[..chunk.key.len()] == chunk.key[..]
                                    {
                                        // This is a chunk of the current value
                                        chunk.bytes.extend_from_slice(cb_value);
                                        continue;
                                    } else {
                                        // Return collected chunked value
                                        if !cb(&chunk.key, &chunk.bytes)? {
                                            return Ok(());
                                        }

                                        // Reset collector
                                        chunked_key = None;
                                    }
                                }

                                if cb_value.len() < MAX_VALUE_SIZE {
                                    if !cb(cb_key, cb_value)? {
                                        return Ok(());
                                    }
                                } else {
                                    // Start collecting chunked value
                                    chunked_key = Some(ChunkedValueCollector {
                                        key: cb_key.to_vec(),
                                        bytes: cb_value.to_vec(),
                                    });
                                }
                            }
                            if values.more() {
                                last_key_ = key.to_vec();
                            }
                        }
                        Ok(None) => {
                            // Return any chunked value collected
                            if let Some(chunked_key) = chunked_key.take() {
                                cb(&chunked_key.key, &chunked_key.bytes)?;
                            }

                            break 'outer;
                        }
                        Err(e) => {
                            drop(values);
                            if e.code() == 1007 && !last_key_.is_empty() {
                                // Transaction is too old to perform reads or be committed
                                last_key = last_key_;
                                continue 'outer;
                            } else if e.is_retryable()
                                && retry_count < MAX_COMMIT_ATTEMPTS
                                && start.elapsed() < MAX_COMMIT_TIME
                            {
                                // Transient error such as a cached read version ahead of lagging
                                // storage servers (code 1009); resume from the last key read,
                                // refresh the read version and back off before retrying.
                                if !last_key_.is_empty() {
                                    last_key = last_key_;
                                }
                                self.version.expire();
                                trx.on_error(e).await.map_err(into_error)?;
                                retry_count += 1;
                                continue 'outer;
                            } else {
                                return Err(into_error(e));
                            }
                        }
                    }
                }
            }
        } else {
            loop {
                let trx = self.read_trx().await?;
                let mut values = trx.get_ranges_keyvalues(
                    RangeOption {
                        begin: KeySelector::first_greater_or_equal(&begin),
                        end: KeySelector::first_greater_than(&end),
                        mode: options::StreamingMode::Small,
                        reverse: !params.ascending,
                        ..Default::default()
                    },
                    true,
                );

                match values.try_next().await {
                    Ok(Some(value)) => {
                        cb(value.key().get(1..).unwrap_or_default(), value.value())?;
                        break;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        drop(values);
                        self.on_read_error(trx, e, &mut retry_count, start).await?;
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into().serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();

        loop {
            let trx = self.read_trx().await?;
            match trx.get(&key, true).await {
                Ok(Some(bytes)) => return deserialize_i64_le(&key, &bytes),
                Ok(None) => return Ok(0),
                Err(e) => {
                    self.on_read_error(trx, e, &mut retry_count, start).await?;
                }
            }
        }
    }

    async fn on_read_error(
        &self,
        trx: Transaction,
        err: FdbError,
        retry_count: &mut u32,
        start: Instant,
    ) -> trc::Result<()> {
        if err.is_retryable()
            && *retry_count < MAX_COMMIT_ATTEMPTS
            && start.elapsed() < MAX_COMMIT_TIME
        {
            // The cached read version may be ahead of lagging storage servers under heavy write
            // load (code 1009); expire it so the retry obtains a fresh read version, then let
            // FoundationDB back off before retrying.
            self.version.expire();
            trx.on_error(err).await.map_err(into_error)?;
            *retry_count += 1;
            Ok(())
        } else {
            Err(into_error(err))
        }
    }

    pub(crate) async fn read_trx(&self) -> trc::Result<Transaction> {
        let trx = self.db.create_trx().map_err(into_error)?;
        let version = self.version.current();
        let age = self.version.age();

        if version != 0 && age < MAX_READ_VERSION_AGE.as_nanos() as u64 {
            if age >= REFRESH_READ_VERSION_AFTER.as_nanos() as u64
                && let Some(_guard) = self.version.try_begin_refresh()
            {
                let read_version = trx.get_read_version().await.map_err(into_error)?;
                self.version.refreshed(read_version);
            } else {
                trx.set_read_version(version);
            }
        } else {
            let read_version = trx.get_read_version().await.map_err(into_error)?;
            self.version.refreshed(read_version);
        }

        Ok(trx)
    }
}

pub(crate) async fn read_chunked_value(
    key: &[u8],
    trx: &Transaction,
    snapshot: bool,
) -> Result<ChunkedValue, FdbError> {
    if let Some(bytes) = trx.get(key, snapshot).await? {
        if bytes.len() < MAX_VALUE_SIZE {
            Ok(ChunkedValue::Single(bytes))
        } else {
            let mut value = Vec::with_capacity(bytes.len() * 2);
            value.extend_from_slice(&bytes);
            let mut key = KeySerializer::new(key.len() + 1)
                .write(key)
                .write(0u8)
                .finalize();

            while let Some(bytes) = trx.get(&key, snapshot).await? {
                value.extend_from_slice(&bytes);
                *key.last_mut().unwrap() += 1;
            }

            Ok(ChunkedValue::Chunked {
                bytes: value,
                n_chunks: *key.last().unwrap(),
            })
        }
    } else {
        Ok(ChunkedValue::None)
    }
}
