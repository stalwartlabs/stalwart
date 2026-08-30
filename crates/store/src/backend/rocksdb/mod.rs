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

const CF_SLOTS: usize = u8::MAX as usize + 1;

pub(crate) struct CfCache<'db> {
    db: &'db OptimisticTransactionDB<MultiThreaded>,
    handles: [Option<Arc<BoundColumnFamily<'db>>>; CF_SLOTS],
}

impl<'db> CfCache<'db> {
    pub(crate) fn new(db: &'db OptimisticTransactionDB<MultiThreaded>) -> Self {
        Self {
            db,
            handles: [const { None }; CF_SLOTS],
        }
    }

    #[inline(always)]
    pub(crate) fn get(&mut self, subspace: Subspace) -> &Arc<BoundColumnFamily<'db>> {
        let db = self.db;

        self.handles[subspace.byte() as usize].get_or_insert_with(|| db.subspace_handle(subspace))
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
