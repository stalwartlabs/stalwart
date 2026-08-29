/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::EphemeralStore;
use crate::{
    Key, Shape, Subspace,
    backend::deserialize_i64_le,
    write::{Advance, AssignedIds, Batch, BatchCursor, LogSet, MergeResult, ValueOp},
};

impl EphemeralStore {
    pub(crate) async fn write(
        &self,
        batch: Batch<'_>,
        result: &mut AssignedIds,
    ) -> trc::Result<()> {
        let mut cursor = BatchCursor::new(&batch);
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        let mut state = self.state.write();

        if batch.has_allocations() {
            let map = state.subspaces.entry(Subspace::Counter).or_default();
            let mut key_buf = Vec::with_capacity(16);

            for allocation in batch.allocations() {
                key_buf.clear();
                allocation.serialize_key_into(&mut key_buf, 0);
                let last_id = match map.get(&key_buf) {
                    Some(bytes) => deserialize_i64_le(&key_buf, bytes)?,
                    None => 0,
                } + allocation.increment_by();
                map.insert(key_buf.clone(), last_id.to_le_bytes().to_vec());
                result.apply(allocation, last_id);
            }
        }

        let mut key_buf = Vec::with_capacity(64);
        for op in batch.ops.iter_mut() {
            match cursor.advance(op, result) {
                Advance::Cursor => {}
                Advance::Value { class, op } => {
                    let subspace = cursor.subspace(class);
                    let key = cursor.value_key_owned(class, 0);
                    let map = state.subspaces.entry(subspace).or_default();

                    match op {
                        ValueOp::Set(value) => {
                            let value = value.resolve(result)?.into_owned();
                            map.insert(key, value);
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let merge_result =
                                (merge_op.0)(result, map.get(&key).map(|v| v.as_slice()))?;

                            match merge_result {
                                MergeResult::Update(value) => {
                                    map.insert(key, value);
                                }
                                MergeResult::Delete => {
                                    map.remove(&key);
                                }
                                MergeResult::Skip => (),
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            let current = match map.get(&key) {
                                Some(bytes) => deserialize_i64_le(&key, bytes)?,
                                None => 0,
                            };
                            let next = current + *by;
                            map.insert(key, next.to_le_bytes().to_vec());
                        }
                        ValueOp::AddAndGet(by) => {
                            let current = match map.get(&key) {
                                Some(bytes) => deserialize_i64_le(&key, bytes)?,
                                None => 0,
                            };
                            let next = current + *by;
                            map.insert(key, next.to_le_bytes().to_vec());
                            result.push_counter_id(next);
                        }
                        ValueOp::Clear => {
                            map.remove(&key);
                        }
                    }
                }
                Advance::Index { field, key, set } => {
                    cursor.index_key(field, key, &mut key_buf, 0);
                    let index_key = key_buf.clone();
                    let map = state.subspaces.entry(Subspace::Indexes).or_default();
                    if set {
                        map.insert(index_key, Vec::new());
                    } else {
                        map.remove(&index_key);
                    }
                }
                Advance::Log { collection, set } => {
                    cursor.log_key(collection, result, &mut key_buf, 0);
                    let log_key = key_buf.clone();
                    let bytes = match set {
                        LogSet::Bytes(bytes) => std::mem::take(bytes),
                        LogSet::Pending(changes) => {
                            changes.serialize_into(
                                collection.is_prefixed(),
                                Some(result),
                                &mut log_scratch,
                                &mut log_buf,
                            );
                            std::mem::take(&mut log_buf)
                        }
                    };
                    let map = state.subspaces.entry(Subspace::Logs).or_default();
                    map.insert(log_key, bytes);
                }
                Advance::Assert {
                    class,
                    assert_value,
                } => {
                    let subspace = cursor.subspace(class);
                    let key = cursor.value_key_owned(class, 0);
                    let matches = state
                        .subspaces
                        .get(&subspace)
                        .and_then(|m| m.get(&key))
                        .map(|v| assert_value.matches(v.as_slice()))
                        .unwrap_or_else(|| assert_value.is_none());

                    if !matches {
                        return Err(trc::StoreEvent::AssertValueFailed.into());
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let subspace = from.subspace();
        let from_key = from.serialize(0);
        let to_key = to.serialize(0);
        let mut state = self.state.write();
        if let Some(map) = state.subspaces.get_mut(&subspace) {
            let keys: Vec<Vec<u8>> = map
                .range(from_key..to_key)
                .map(|(k, _)| k.clone())
                .collect();
            for k in keys {
                map.remove(&k);
            }
        }
        Ok(())
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let mut state = self.state.write();
        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
        {
            if let Some(map) = state.subspaces.get_mut(&subspace) {
                let keys: Vec<Vec<u8>> = map
                    .iter()
                    .filter_map(|(k, v)| {
                        if v.len() == std::mem::size_of::<i64>()
                            && i64::from_le_bytes(v[..].try_into().unwrap()) == 0
                        {
                            Some(k.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                for k in keys {
                    map.remove(&k);
                }
            }
        }
        Ok(())
    }
}
