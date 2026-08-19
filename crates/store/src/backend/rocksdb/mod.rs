/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Subspace;
use rocksdb::{BoundColumnFamily, MultiThreaded, OptimisticTransactionDB};
use std::sync::Arc;

pub mod blob;
pub mod main;
pub mod read;
pub mod write;

static CF_LOGS: &str = Subspace::Logs.name();
static CF_INDEXES: &str = Subspace::Indexes.name();
static CF_BLOBS: &str = Subspace::Blobs.name();

pub(crate) trait CfHandle {
    fn subspace_handle(&self, subspace: Subspace) -> Arc<BoundColumnFamily<'_>>;
}

impl CfHandle for OptimisticTransactionDB<MultiThreaded> {
    #[inline(always)]
    fn subspace_handle(&self, subspace: Subspace) -> Arc<BoundColumnFamily<'_>> {
        self.cf_handle(subspace.name()).unwrap()
    }
}

pub struct RocksDbStore {
    db: Arc<OptimisticTransactionDB<MultiThreaded>>,
    worker_pool: rayon::ThreadPool,
}

#[inline(always)]
fn into_error(err: rocksdb::Error) -> trc::Error {
    trc::StoreEvent::RocksdbError.reason(err)
}
