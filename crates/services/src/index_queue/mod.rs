/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};
use store::{
    ahash::{AHashMap, AHashSet},
    search::IndexDocument,
    write::{SearchIndex, SearchIndexClass, ValueClass},
};
use tokio::sync::{mpsc, oneshot};

pub mod document;
pub mod index;
pub mod manager;
pub mod reindex;

const LOCK_EXPIRY: u64 = 10 * 60;
const LOCK_MARGIN: Duration = Duration::from_secs(60);
const FULL_SCAN_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MIN_SCAN_INTERVAL: Duration = Duration::from_millis(100);
const BULK_LINGER: Duration = Duration::from_millis(50);
const CANDIDATE_OVERSCAN: usize = 4;
const ITEM_OVERSCAN: usize = 4;
const MAX_DELETE_CLAUSES: usize = 256;
const REINDEX_CHUNK_SIZE: usize = 10000;
const MIN_RETRY_DELAY: u64 = 30;
const MAX_RETRY_DELAY: u64 = 30 * 60;
const LOCKED_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Partition {
    index: SearchIndex,
    partition: u32,
}

#[derive(Debug)]
pub(crate) struct QueuedItem {
    id_prefix: u32,
    id_suffix: u32,
    created_at: u64,
    insert: bool,
}

#[derive(Debug)]
pub(crate) struct PendingItem {
    id_prefix: u32,
    id_suffix: u32,
    insert: bool,
}

#[derive(Debug)]
pub(crate) struct Deletion {
    index: SearchIndex,
    account_id: u32,
    document_id: u32,
}

#[derive(Debug)]
pub(crate) enum PartitionOutcome {
    Completed,
    Locked,
    Incomplete,
    Failed(String),
}

#[derive(Debug)]
pub(crate) struct PartitionResult {
    partition: Partition,
    outcome: PartitionOutcome,
}

#[derive(Debug, Default)]
pub(crate) struct IndexQueueState {
    claimed: AHashSet<Partition>,
    failed: AHashMap<Partition, u32>,
    deferred: AHashMap<Partition, Instant>,
    cursor: Option<Partition>,
    scan_failures: u32,
}

pub(crate) enum Sink {
    Internal,
    Bulk(mpsc::Sender<BulkRequest>),
}

pub(crate) struct BulkRequest {
    documents: Vec<IndexDocument>,
    deletions: Vec<Deletion>,
    ack: oneshot::Sender<Result<(), String>>,
}

impl Partition {
    fn queue_class(&self, item: &QueuedItem) -> ValueClass {
        ValueClass::SearchIndex(SearchIndexClass::Queue {
            index: self.index,
            id_prefix: item.id_prefix,
            id_suffix: item.id_suffix,
            created_at: item.created_at,
        })
    }

    fn index_class(&self) -> ValueClass {
        ValueClass::SearchIndex(SearchIndexClass::QueueIndex {
            index: self.index,
            partition: self.partition,
        })
    }

    fn status_class(&self) -> ValueClass {
        ValueClass::SearchIndex(SearchIndexClass::QueueStatus {
            index: self.index,
            partition: self.partition,
        })
    }
}

impl QueuedItem {
    fn is_same_document(&self, other: &QueuedItem) -> bool {
        self.id_prefix == other.id_prefix && self.id_suffix == other.id_suffix
    }
}

impl PendingItem {
    fn document_id(&self) -> u64 {
        ((self.id_prefix as u64) << 32) | self.id_suffix as u64
    }
}
