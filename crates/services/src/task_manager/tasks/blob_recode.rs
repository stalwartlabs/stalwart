/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::outcome::Outcome;
use common::Server;
use registry::schema::{
    enums::{CompressionAlgo, TaskBlobRecodeCompression},
    structs::{Task, TaskBlobRecode, TaskBlobRecodeEncryption, TaskStatus},
};
use std::time::Instant;
use store::write::{
    BatchBuilder,
    blob_codec::{BlobEncryption, BlobFormat, BlobOpts},
    now,
};
use trc::{AddContext, StoreEvent};
use types::blob_hash::BlobHash;

pub(crate) trait BlobRecodeTask: Sync + Send {
    fn blob_recode(&self, task: &TaskBlobRecode) -> impl Future<Output = Outcome> + Send;
}

impl BlobRecodeTask for Server {
    async fn blob_recode(&self, task: &TaskBlobRecode) -> Outcome {
        match BlobRecoder::run(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(err.details("Failed to perform blob recode task"));
                result
            }
        }
    }
}

struct BlobRecoder<'x> {
    server: &'x Server,
    compression: Option<CompressionAlgo>,
    encryption: Option<BlobEncryption>,
}

enum RecodeResult {
    Rewritten,
    Skipped,
}

impl<'x> BlobRecoder<'x> {
    async fn run(server: &'x Server, task: &TaskBlobRecode) -> trc::Result<Outcome> {
        let Some(shard_index) = task.shard_index else {
            BlobRecoder::schedule_shards(server, task).await?;
            return Ok(Outcome::done());
        };
        let Ok(shard_index) = u8::try_from(shard_index) else {
            return Ok(Outcome::fatal("Blob shard index out of range"));
        };

        let compression = match task.compression {
            TaskBlobRecodeCompression::Keep => None,
            TaskBlobRecodeCompression::Disable => Some(CompressionAlgo::None),
            TaskBlobRecodeCompression::Lz4 => Some(CompressionAlgo::Lz4),
            TaskBlobRecodeCompression::Zstd => Some(CompressionAlgo::Zstd),
        };
        let encryption = match &task.encryption {
            TaskBlobRecodeEncryption::Keep => None,
            TaskBlobRecodeEncryption::Disable => Some(BlobEncryption::None),
            TaskBlobRecodeEncryption::Encrypt(target) => {
                match u32::try_from(target.key_id.id())
                    .ok()
                    .and_then(|id| server.core.blob.keys.get(id))
                {
                    Some(key) => Some(BlobEncryption::Key(key.clone())),
                    None => return Ok(Outcome::transient("Blob encryption key is not loaded")),
                }
            }
        };
        if compression.is_none() && encryption.is_none() {
            return Ok(Outcome::done());
        }

        let recoder = BlobRecoder {
            server,
            compression,
            encryption,
        };
        recoder.recode_shard(shard_index).await
    }

    async fn recode_shard(&self, shard_index: u8) -> trc::Result<Outcome> {
        let started = Instant::now();
        let hashes = self
            .server
            .store()
            .user_blob_hashes(shard_index)
            .await
            .caused_by(trc::location!())?;
        let mut rewritten = 0u64;
        let mut failed = 0u64;

        for hash in &hashes {
            match self.recode_blob(hash).await {
                Ok(RecodeResult::Rewritten) => rewritten += 1,
                Ok(RecodeResult::Skipped) => {}
                Err(err) => {
                    failed += 1;
                    trc::error!(
                        err.ctx(trc::Key::BlobId, hash.to_hex())
                            .details("Failed to recode blob")
                    );
                }
            }
        }

        trc::event!(
            Store(StoreEvent::BlobStoreRecoded),
            Partition = shard_index as u16,
            Total = hashes.len(),
            TotalSuccesses = rewritten,
            TotalFailures = failed,
            Elapsed = started.elapsed()
        );

        if failed == 0 {
            Ok(Outcome::done())
        } else {
            Ok(Outcome::transient(format!(
                "{failed} blobs in shard {shard_index} could not be recoded"
            )))
        }
    }

    async fn recode_blob(&self, hash: &BlobHash) -> trc::Result<RecodeResult> {
        let blob_store = self.server.blob_store();
        let Some(raw) = blob_store
            .get_raw_blob(hash.as_slice())
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(RecodeResult::Skipped);
        };
        let current = BlobFormat::of(&raw);
        let (current_compression, current_key_id) = current
            .map_or((CompressionAlgo::None, None), |format| {
                (format.compression, format.key_id)
            });
        let keys = &self.server.core.blob.keys;
        let target_compression = self.compression.unwrap_or(current_compression);
        let encryption = match (&self.encryption, current_key_id) {
            (Some(encryption), _) => encryption.clone(),
            (None, Some(key_id)) => keys
                .get(key_id)
                .map_or(BlobEncryption::Unavailable(key_id), |key| {
                    BlobEncryption::Key(key.clone())
                }),
            (None, None) => BlobEncryption::None,
        };
        let target_key_id = match &encryption {
            BlobEncryption::None => None,
            BlobEncryption::Key(key) => Some(key.id()),
            BlobEncryption::Unavailable(key_id) => Some(*key_id),
        };
        if current.is_some()
            && current_compression == target_compression
            && current_key_id == target_key_id
        {
            return Ok(RecodeResult::Skipped);
        }

        let data = keys.decode(hash.as_slice(), raw)?;
        if !self
            .server
            .store()
            .blob_exists(hash)
            .await
            .caused_by(trc::location!())?
        {
            return Ok(RecodeResult::Skipped);
        }
        blob_store
            .replace_blob(
                hash.as_slice(),
                &data,
                &BlobOpts::new(target_compression, encryption),
            )
            .await
            .caused_by(trc::location!())?;

        Ok(RecodeResult::Rewritten)
    }

    async fn schedule_shards(server: &Server, task: &TaskBlobRecode) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        let now = now() as i64;
        for shard_index in 0..=u8::MAX {
            batch.schedule_task(Task::BlobRecode(TaskBlobRecode {
                compression: task.compression,
                encryption: task.encryption.clone(),
                shard_index: Some(shard_index as u64),
                status: TaskStatus::at(now),
            }));

            if batch.is_large_batch() {
                server.commit_batch(batch).await?;
                batch = BatchBuilder::new();
            }
        }

        if !batch.is_empty() {
            server.commit_batch(batch).await?;
        }

        Ok(())
    }
}
