/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MAX_VALUE_SIZE,
    window::{WindowLoad, read_keys},
};
use crate::{
    WITH_SUBSPACE,
    write::{Advance, AssignedIds, Batch, BatchCursor, Operation, ValueOp},
};
use ahash::AHashSet;
use fdb::Transaction;
use std::ops::Range;
use xxhash_rust::xxh3::xxh3_64;

const MIN_PREREAD_MERGES: usize = 2;

enum Slot {
    Sequential,
    Missing,
    Value(Range<usize>),
    Head(Range<usize>),
}

pub(super) enum Prefetched<'x> {
    Value(Option<&'x [u8]>),
    Head(&'x [u8]),
    Sequential,
}

#[derive(Default)]
pub(super) struct MergePreRead {
    keys: Vec<u8>,
    reads: Vec<(Range<usize>, usize)>,
    values: Vec<u8>,
    slots: Vec<Slot>,
    next: usize,
}

fn window_reads<'k>(
    keys: &'k [u8],
    reads: &'k [(Range<usize>, usize)],
) -> impl Iterator<Item = (usize, &'k [u8])> + use<'k> {
    reads
        .iter()
        .enumerate()
        .filter_map(move |(index, (range, _))| keys.get(range.clone()).map(|key| (index, key)))
}

impl MergePreRead {
    pub(super) fn plan(batch: &mut Batch<'_>, ids: &mut AssignedIds) -> Option<Self> {
        let merges = batch
            .ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Operation::Value {
                        op: ValueOp::MergeFnc(_),
                        ..
                    }
                )
            })
            .take(MIN_PREREAD_MERGES)
            .count();
        if merges < MIN_PREREAD_MERGES {
            return None;
        }

        let mark = ids.mark();
        let mut plan = MergePreRead::default();
        let mut cursor = BatchCursor::new(batch);
        let mut written = AHashSet::new();
        let mut range_cleared = false;
        let mut key = Vec::with_capacity(64);
        for op in batch.ops.iter_mut() {
            match cursor.advance(op, ids) {
                Advance::Value { class, op } => {
                    cursor.value_key(class, &mut key, WITH_SUBSPACE);
                    let first_write = written.insert(xxh3_64(&key));
                    match op {
                        ValueOp::MergeFnc(_) if first_write && !range_cleared => {
                            let start = plan.keys.len();
                            plan.keys.extend_from_slice(&key);
                            plan.reads.push((start..plan.keys.len(), plan.slots.len()));
                            plan.slots.push(Slot::Missing);
                        }
                        ValueOp::MergeFnc(_) => plan.slots.push(Slot::Sequential),
                        _ => {}
                    }
                }
                Advance::ClearRange { .. } => range_cleared = true,
                _ => {}
            }
        }
        ids.rollback(mark);
        Some(plan)
    }

    pub(super) async fn read(
        &mut self,
        trx: &mut Transaction<'_>,
        load: &WindowLoad,
    ) -> fdb::Result<()> {
        let MergePreRead {
            keys,
            reads,
            values,
            slots,
            next,
            ..
        } = self;
        *next = 0;
        values.clear();
        for (_, slot) in reads.iter() {
            if let Some(slot) = slots.get_mut(*slot) {
                *slot = Slot::Missing;
            }
        }
        read_keys(trx, load, window_reads(keys, reads), |index, value| {
            if let Some(slot) = reads.get(index).and_then(|(_, slot)| slots.get_mut(*slot)) {
                let start = values.len();
                values.extend_from_slice(value);
                *slot = if value.len() < MAX_VALUE_SIZE {
                    Slot::Value(start..values.len())
                } else {
                    Slot::Head(start..values.len())
                };
            }
        })
        .await
    }

    pub(super) fn prefetched(&self) -> impl Iterator<Item = (&[u8], Option<&[u8]>)> {
        self.reads.iter().filter_map(|(key, slot)| {
            let key = self.keys.get(key.clone())?;
            match self.slots.get(*slot)? {
                Slot::Value(value) => Some((key, Some(self.values.get(value.clone())?))),
                Slot::Missing => Some((key, None)),
                Slot::Head(_) | Slot::Sequential => None,
            }
        })
    }

    pub(super) fn next_merge(&mut self) -> Prefetched<'_> {
        let index = self.next;
        self.next += 1;
        match self.slots.get(index) {
            Some(Slot::Value(range)) => self
                .values
                .get(range.clone())
                .map_or(Prefetched::Sequential, |value| {
                    Prefetched::Value(Some(value))
                }),
            Some(Slot::Head(range)) => self
                .values
                .get(range.clone())
                .map_or(Prefetched::Sequential, Prefetched::Head),
            Some(Slot::Missing) => Prefetched::Value(None),
            Some(Slot::Sequential) | None => Prefetched::Sequential,
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb/preread/tests.rs"]
mod tests;
