/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::EphemeralStore;
use crate::{
    IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER, SUBSPACE_INDEXES,
    SUBSPACE_LOGS, SUBSPACE_QUOTA,
    backend::deserialize_i64_le,
    write::{AssignedIds, Batch, MergeResult, Operation, ValueClass, ValueOp},
};

impl EphemeralStore {
    pub(crate) async fn write(&self, batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = 0u64;
        let mut result = AssignedIds::default();
        let has_changes = !batch.changes.is_empty();

        let mut state = self.state.write();

        if has_changes {
            let map = state.subspaces.entry(SUBSPACE_COUNTER).or_default();
            for &account_id in batch.changes.keys() {
                let key = ValueClass::ChangeId.serialize(account_id, 0, 0, 0);
                let next = match map.get(&key) {
                    Some(bytes) => deserialize_i64_le(&key, bytes)? + 1,
                    None => 1,
                };
                map.insert(key, next.to_le_bytes().to_vec());
                result.push_change_id(account_id, next as u64);
            }
        }

        for op in batch.ops.iter_mut() {
            match op {
                Operation::AccountId {
                    account_id: account_id_,
                } => {
                    account_id = *account_id_;
                    if has_changes {
                        change_id = result.set_current_change_id(account_id)?;
                    }
                }
                Operation::Collection {
                    collection: collection_,
                } => {
                    collection = u8::from(*collection_);
                }
                Operation::DocumentId {
                    document_id: document_id_,
                } => {
                    document_id = *document_id_;
                }
                Operation::Value { class, op } => {
                    let subspace = class.subspace(collection);
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let map = state.subspaces.entry(subspace).or_default();

                    match op {
                        ValueOp::Set(value) => {
                            map.insert(key, std::mem::take(value));
                        }
                        ValueOp::SetFnc(set_op) => {
                            let value = (set_op.fnc)(&set_op.params, &result)?;
                            map.insert(key, value);
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let merge_result = (merge_op.fnc)(
                                &merge_op.params,
                                &result,
                                map.get(&key).map(|v| v.as_slice()),
                            )?;

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
                Operation::Index { field, key, set } => {
                    let index_key = IndexKey {
                        account_id,
                        collection,
                        document_id,
                        field: *field,
                        key: key.as_slice(),
                    }
                    .serialize(0);
                    let map = state.subspaces.entry(SUBSPACE_INDEXES).or_default();
                    if *set {
                        map.insert(index_key, Vec::new());
                    } else {
                        map.remove(&index_key);
                    }
                }
                Operation::Log { collection, set } => {
                    let log_key = LogKey {
                        account_id,
                        collection: u8::from(*collection),
                        change_id,
                    }
                    .serialize(0);
                    let map = state.subspaces.entry(SUBSPACE_LOGS).or_default();
                    map.insert(log_key, std::mem::take(set));
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let subspace = class.subspace(collection);
                    let key = class.serialize(account_id, collection, document_id, 0);
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

        Ok(result)
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
        for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER] {
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
