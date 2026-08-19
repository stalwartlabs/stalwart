/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::RocksDbStore;
use crate::*;
use ::registry::schema::structs;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, MergeOperands,
    OptimisticTransactionDB, Options,
};
use std::path::PathBuf;
use tokio::sync::oneshot;

const MIN_WRITE_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const MAX_WRITE_BUFFER_SIZE: usize = 64 * 1024 * 1024;
const MIN_DB_WRITE_BUFFER_SIZE: usize = 32 * 1024 * 1024;
const BLOOM_BITS_PER_KEY: f64 = 10.0;
const SCAN_BLOCK_SIZE: usize = 16 * 1024;
const CHURN_TARGET_FILE_SIZE: u64 = 16 * 1024 * 1024;
const CHURN_DELETION_WINDOW: usize = 4096;
const CHURN_DELETION_TRIGGER: usize = 1024;
const CHURN_DELETION_RATIO: f64 = 0.5;
const BYTES_PER_SYNC: u64 = 1024 * 1024;
const COLD_MIN_BLOB_SIZE: u64 = 16 * 1024;

#[derive(Clone, Copy)]
enum CfProfile {
    /// Read through `get_value` / `key_exists`, so a whole key bloom filter pays off.
    PointLookup,
    /// Read only through `iterate`, which never consults a whole key bloom filter.
    Scan,
    /// Point read and point deleted at a high rate.
    Churn,
    /// Scanned from the oldest key and point deleted once consumed, with empty values.
    Queue,
    /// Counters updated through the merge operator.
    Counter,
    /// Blob values held in RocksDB blob files.
    Blob,
    /// Write-once values, large ones offloaded to RocksDB blob files.
    Cold,
}

trait RocksDbProfile {
    fn profile(self) -> CfProfile;
}

impl RocksDbProfile for Subspace {
    fn profile(self) -> CfProfile {
        match self {
            Subspace::Counter
            | Subspace::Quota
            | Subspace::InMemoryCounter
            | Subspace::GlobalCounter => CfProfile::Counter,
            Subspace::Blobs => CfProfile::Blob,
            Subspace::Immutable => CfProfile::Cold,
            Subspace::Indexes
            | Subspace::Acl
            | Subspace::Logs
            | Subspace::TelemetryMetric
            | Subspace::SearchTerm
            | Subspace::RegistryIndex
            | Subspace::IndexProperty => CfProfile::Scan,
            Subspace::TaskQueue
            | Subspace::DeletedItems
            | Subspace::BlobLink
            | Subspace::InMemoryValue
            | Subspace::QueueMessage
            | Subspace::ReportOut
            | Subspace::ReportIn
            | Subspace::SpamSamples => CfProfile::Churn,
            Subspace::Property
            | Subspace::Registry
            | Subspace::TelemetrySpan
            | Subspace::RegistryPrimaryKey
            | Subspace::Directory
            | Subspace::SearchDocument
            | Subspace::System => CfProfile::PointLookup,
            Subspace::QueueEvent | Subspace::SearchQueue => CfProfile::Queue,
        }
    }
}

impl RocksDbStore {
    pub async fn open(config: structs::RocksDbStore) -> Result<Store, String> {
        // Create the database directory if it doesn't exist
        let idx_path: PathBuf = PathBuf::from(config.path);
        std::fs::create_dir_all(&idx_path).map_err(|err| {
            format!(
                "Failed to create database directory {}: {:?}",
                idx_path.display(),
                err
            )
        })?;

        let cache = Cache::new_lru_cache(config.cache_size as usize);
        let write_buffer_size =
            ((config.buffer_size as usize) / 4).clamp(MIN_WRITE_BUFFER_SIZE, MAX_WRITE_BUFFER_SIZE);
        let mut cfs = Vec::new();

        for subspace in Subspace::ALL.iter().copied() {
            let profile = subspace.profile();
            let mut cf_opts = cf_options(profile, &cache, write_buffer_size);

            if let Some(min_blob_size) = match profile {
                CfProfile::Blob => Some(config.blob_size),
                CfProfile::Cold => Some(COLD_MIN_BLOB_SIZE),
                _ => None,
            } {
                cf_opts.set_enable_blob_files(true);
                cf_opts.set_min_blob_size(min_blob_size);
                cf_opts.set_enable_blob_gc(true);
                cf_opts.set_blob_gc_age_cutoff(1.0);
                cf_opts.set_blob_gc_force_threshold(0.5);
            }

            cfs.push(ColumnFamilyDescriptor::new(subspace.name(), cf_opts));
        }

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        db_opts.set_max_background_jobs(std::cmp::max(num_cpus::get() as i32, 3));
        db_opts.increase_parallelism(std::cmp::max(num_cpus::get() as i32, 3));
        db_opts
            .set_db_write_buffer_size((config.buffer_size as usize).max(MIN_DB_WRITE_BUFFER_SIZE));
        db_opts.set_bytes_per_sync(BYTES_PER_SYNC);
        db_opts.set_wal_bytes_per_sync(BYTES_PER_SYNC);

        Ok(Store::RocksDb(Arc::new(RocksDbStore {
            db: OptimisticTransactionDB::open_cf_descriptors(&db_opts, idx_path, cfs)
                .map_err(|err| format!("Failed to open database: {:?}", err))?
                .into(),
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(std::cmp::max(
                    config
                        .pool_workers
                        .filter(|v| *v > 0)
                        .map(|v| v as usize)
                        .unwrap_or_else(num_cpus::get),
                    4,
                ))
                .build()
                .map_err(|err| format!("Failed to build worker pool: {:?}", err))?,
        })))
    }

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.scope(|s| {
            s.spawn(|_| {
                tx.send(f()).ok();
            });
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err)),
        }
    }
}

pub fn numeric_value_merge(
    _key: &[u8],
    value: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let mut value = if let Some(value) = value {
        i64::from_le_bytes(value.try_into().ok()?)
    } else {
        0
    };

    for op in operands.iter() {
        value += i64::from_le_bytes(op.try_into().ok()?);
    }

    let mut bytes = Vec::with_capacity(std::mem::size_of::<i64>());
    bytes.extend_from_slice(&value.to_le_bytes());
    Some(bytes)
}

fn cf_options(profile: CfProfile, cache: &Cache, write_buffer_size: usize) -> Options {
    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(cache);
    block_opts.set_cache_index_and_filter_blocks(true);
    block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

    let mut opts = Options::default();
    opts.set_write_buffer_size(write_buffer_size);
    opts.set_max_write_buffer_number(4);

    match profile {
        CfProfile::PointLookup => {
            block_opts.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
            opts.set_compression_type(DBCompressionType::Lz4);
        }
        CfProfile::Scan => {
            block_opts.set_block_size(SCAN_BLOCK_SIZE);
            opts.set_compression_type(DBCompressionType::Lz4);
        }
        CfProfile::Churn => {
            block_opts.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
            opts.set_compression_type(DBCompressionType::Lz4);
            opts.set_target_file_size_base(CHURN_TARGET_FILE_SIZE);
            opts.add_compact_on_deletion_collector_factory(
                CHURN_DELETION_WINDOW,
                CHURN_DELETION_TRIGGER,
                CHURN_DELETION_RATIO,
            );
        }
        CfProfile::Queue => {
            block_opts.set_block_size(SCAN_BLOCK_SIZE);
            opts.set_compression_type(DBCompressionType::None);
            opts.set_target_file_size_base(CHURN_TARGET_FILE_SIZE);
            opts.add_compact_on_deletion_collector_factory(
                CHURN_DELETION_WINDOW,
                CHURN_DELETION_TRIGGER,
                CHURN_DELETION_RATIO,
            );
        }
        CfProfile::Counter => {
            block_opts.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
            opts.set_compression_type(DBCompressionType::None);
            opts.set_merge_operator_associative("merge", numeric_value_merge);
        }
        CfProfile::Blob => {
            block_opts.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
            opts.set_compression_type(DBCompressionType::None);
        }
        CfProfile::Cold => {
            block_opts.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
            opts.set_compression_type(DBCompressionType::Lz4);
        }
    }

    opts.set_block_based_table_factory(&block_opts);

    opts
}
