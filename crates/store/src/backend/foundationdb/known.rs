/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::read::ChunkedValue;
use crate::{
    WITH_SUBSPACE,
    write::{Advance, AssignedIds, Batch, BatchCursor, Operation, ValueOp},
};
use ahash::AHashMap;
use fdb::Bytes;
use std::{collections::hash_map::Entry, ops::Range};
use xxhash_rust::xxh3::xxh3_64;

const MIN_REPEATED_READS: usize = 2;

struct Known {
    key: Range<usize>,
    repeated: bool,
    value: Option<ChunkedValue>,
}

#[derive(Default)]
pub(super) struct KnownValues {
    keys: Vec<u8>,
    slots: Vec<(u64, usize)>,
    known: Vec<Known>,
}

impl KnownValues {
    pub(super) fn plan(batch: &mut Batch<'_>, ids: &mut AssignedIds) -> Self {
        let mut plan = KnownValues::default();
        let reads = batch
            .ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Operation::Value {
                        op: ValueOp::MergeFnc(_) | ValueOp::AddAndGet(_),
                        ..
                    } | Operation::AssertValue { .. }
                )
            })
            .take(MIN_REPEATED_READS)
            .count();
        if reads < MIN_REPEATED_READS {
            return plan;
        }

        let mark = ids.mark();
        let mut cursor = BatchCursor::new(batch);
        let mut slots: AHashMap<u64, usize> = AHashMap::new();
        let mut key = Vec::with_capacity(64);
        for op in batch.ops.iter_mut() {
            let class = match cursor.advance(op, ids) {
                Advance::Value {
                    class,
                    op: ValueOp::MergeFnc(_) | ValueOp::AddAndGet(_),
                }
                | Advance::Assert { class, .. } => class,
                _ => continue,
            };
            cursor.value_key(class, &mut key, WITH_SUBSPACE);
            match slots.entry(xxh3_64(&key)) {
                Entry::Occupied(slot) => {
                    if let Some(known) = plan.known.get_mut(*slot.get()) {
                        known.repeated = true;
                    }
                }
                Entry::Vacant(slot) => {
                    let start = plan.keys.len();
                    plan.keys.extend_from_slice(&key);
                    slot.insert(plan.known.len());
                    plan.known.push(Known {
                        key: start..plan.keys.len(),
                        repeated: false,
                        value: None,
                    });
                }
            }
        }
        ids.rollback(mark);

        plan.slots.extend(
            slots
                .into_iter()
                .filter(|(_, slot)| plan.known.get(*slot).is_some_and(|known| known.repeated)),
        );
        plan.slots.sort_unstable_by_key(|(hash, _)| *hash);
        plan
    }

    pub(super) fn seed<'x>(
        &mut self,
        prefetched: impl Iterator<Item = (&'x [u8], Option<&'x [u8]>)>,
    ) {
        if self.slots.is_empty() {
            return;
        }
        for (key, value) in prefetched {
            if let Some(slot) = self.slot(key) {
                self.update(Some(slot), || {
                    Some(value.map_or(ChunkedValue::None, |value| {
                        ChunkedValue::Single(Bytes::copy_from_slice(value))
                    }))
                });
            }
        }
    }

    pub(super) fn slot(&self, key: &[u8]) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let hash = xxh3_64(key);
        let index = self
            .slots
            .binary_search_by_key(&hash, |(hash, _)| *hash)
            .ok()?;
        self.slots.get(index).map(|(_, slot)| *slot).filter(|slot| {
            self.known
                .get(*slot)
                .and_then(|known| self.keys.get(known.key.clone()))
                == Some(key)
        })
    }

    pub(super) fn get(&self, slot: Option<usize>) -> Option<&ChunkedValue> {
        slot.and_then(|slot| self.known.get(slot))
            .and_then(|known| known.value.as_ref())
    }

    pub(super) fn update(
        &mut self,
        slot: Option<usize>,
        value: impl FnOnce() -> Option<ChunkedValue>,
    ) {
        if let Some(known) = slot.and_then(|slot| self.known.get_mut(slot)) {
            known.value = value();
        }
    }

    pub(super) fn forget(&mut self, slot: Option<usize>) {
        self.update(slot, || None);
    }

    pub(super) fn forget_all(&mut self) {
        for known in &mut self.known {
            known.value = None;
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb/known/tests.rs"]
mod tests;
