/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FdbStore, MAX_VALUE_SIZE, into_error};
use crate::{
    Subspace,
    write::{MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, commit_backoff, key::KeySerializer},
};
use foundationdb::{FdbError, KeySelector, RangeOption, Transaction, options};
use futures::TryStreamExt;
use std::{ops::Range, time::Instant};

const BLOB_CHUNK_LEN: usize = std::mem::size_of::<u16>();

impl FdbStore {
    fn blob_chunk_key(key: &[u8], chunk: u16) -> Vec<u8> {
        KeySerializer::new(key.len() + 1 + BLOB_CHUNK_LEN)
            .write(Subspace::Blobs.byte())
            .write(key)
            .write(chunk)
            .finalize()
    }

    fn blob_chunk_range(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut end = Self::blob_chunk_key(key, u16::MAX);
        end.push(0);

        (Self::blob_chunk_key(key, 0), end)
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let block_start = range.start / MAX_VALUE_SIZE;
        let bytes_start = range.start % MAX_VALUE_SIZE;
        let blob_range = range.end.saturating_sub(range.start);

        if block_start > u16::MAX as usize {
            return Ok(None);
        }

        let begin = Self::blob_chunk_key(key, block_start as u16);
        let (_, end) = Self::blob_chunk_range(key);
        let chunk_key_len = begin.len();
        let mut retry_count = 0;
        let start = Instant::now();
        let mut blob_data: Option<Vec<u8>> = None;
        let mut last_key: Vec<u8> = Vec::new();
        let mut trx = self.read_trx().await?;

        loop {
            match Self::read_blob(
                &trx,
                &begin,
                &end,
                &mut last_key,
                &mut blob_data,
                chunk_key_len,
                bytes_start,
                blob_range,
            )
            .await
            {
                Ok(()) => return Ok(blob_data),
                Err(err) => {
                    trx = self
                        .on_read_error(trx, err, &mut retry_count, start)
                        .await?;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_blob(
        trx: &Transaction,
        begin: &[u8],
        end: &[u8],
        last_key: &mut Vec<u8>,
        blob_data: &mut Option<Vec<u8>>,
        chunk_key_len: usize,
        bytes_start: usize,
        blob_range: usize,
    ) -> Result<(), FdbError> {
        let begin_selector = if last_key.is_empty() {
            KeySelector::first_greater_or_equal(begin)
        } else {
            KeySelector::first_greater_than(last_key.clone())
        };
        let mut chunks = trx.get_ranges_keyvalues(
            RangeOption {
                begin: begin_selector,
                end: KeySelector::first_greater_or_equal(end),
                mode: options::StreamingMode::WantAll,
                ..Default::default()
            },
            true,
        );

        while let Some(chunk) = chunks.try_next().await? {
            let chunk_key = chunk.key();
            if chunk_key.len() != chunk_key_len {
                continue;
            }
            last_key.clear();
            last_key.extend_from_slice(chunk_key);
            let value = chunk.value();

            match blob_data {
                Some(blob_data) => {
                    blob_data.extend_from_slice(
                        value
                            .get(
                                ..std::cmp::min(
                                    blob_range.saturating_sub(blob_data.len()),
                                    value.len(),
                                ),
                            )
                            .unwrap_or(&[]),
                    );
                    if blob_data.len() == blob_range {
                        break;
                    }
                }
                None => {
                    let blob_size = if blob_range <= (5 * (1 << 20)) {
                        blob_range
                    } else if value.len() == MAX_VALUE_SIZE {
                        MAX_VALUE_SIZE * 2
                    } else {
                        value.len()
                    };
                    let mut data = Vec::with_capacity(blob_size);
                    data.extend_from_slice(
                        value
                            .get(
                                bytes_start
                                    ..std::cmp::min(
                                        bytes_start.saturating_add(blob_range),
                                        value.len(),
                                    ),
                            )
                            .unwrap_or(&[]),
                    );
                    let is_done = data.len() == blob_range;
                    *blob_data = Some(data);
                    if is_done {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        const N_CHUNKS: usize = (1 << 5) - 1;

        let chunks = data.chunks(MAX_VALUE_SIZE).collect::<Vec<_>>();
        if chunks.len() > u16::MAX as usize + 1 {
            return Err(trc::StoreEvent::FoundationdbError
                .ctx(trc::Key::Reason, "Blob exceeds the maximum chunk count"));
        }

        for (pos, group) in chunks.chunks(N_CHUNKS).enumerate() {
            self.put_blob_chunks(key, pos * N_CHUNKS, group).await?;
        }

        Ok(())
    }

    async fn put_blob_chunks(
        &self,
        key: &[u8],
        first_chunk: usize,
        chunks: &[&[u8]],
    ) -> trc::Result<()> {
        let start = Instant::now();
        let mut retry_count = 0;

        loop {
            let trx = self.db.create_trx().map_err(into_error)?;
            for (pos, bytes) in chunks.iter().enumerate() {
                trx.set(
                    &Self::blob_chunk_key(key, (first_chunk + pos) as u16),
                    bytes,
                );
            }

            if self
                .commit(
                    trx,
                    retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME,
                )
                .await?
            {
                return Ok(());
            }

            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        if key.is_empty() {
            return Ok(false);
        }

        let (begin, end) = Self::blob_chunk_range(key);
        let start = Instant::now();
        let mut retry_count = 0;

        loop {
            let trx = self.db.create_trx().map_err(into_error)?;
            trx.clear_range(&begin, &end);

            if self
                .commit(
                    trx,
                    retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME,
                )
                .await?
            {
                return Ok(true);
            }

            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }
}
