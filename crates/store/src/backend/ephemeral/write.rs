/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::EphemeralStore;
use crate::{
    IndexKey, Key, LogKey, Shape, Subspace,
    backend::deserialize_i64_le,
    write::{AssignedIds, Batch, LogSet, MergeResult, Operation, ValueClass, ValueOp},
};
use types::collection::SyncCollection;

impl EphemeralStore {
    pub(crate) async fn write(
        &self,
        batch: Batch<'_>,
        result: &mut AssignedIds,
    ) -> trc::Result<()> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut change_group = SyncCollection::None.change_group();
        let mut document_id = u32::MAX;
        let has_changes = !batch.change_accounts.is_empty();
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        let mut state = self.state.write();

        if batch.has_allocations() {
            let map = state.subspaces.entry(Subspace::Counter).or_default();
            let mut key_buf = Vec::with_capacity(16);

            for account in batch.change_accounts {
                key_buf.clear();
                ValueClass::ChangeId(account.group).serialize_into(
                    &mut key_buf,
                    account.account_id,
                    0,
                    0,
                    0,
                );
                let next = match map.get(&key_buf) {
                    Some(bytes) => deserialize_i64_le(&key_buf, bytes)? + 1,
                    None => 1,
                };
                map.insert(key_buf.clone(), next.to_le_bytes().to_vec());
                result.push_change_id(account.account_id, account.group, next as u64);
            }

            for reservation in batch.reservations {
                reservation.serialize_key_into(&mut key_buf, 0);
                let next = match map.get(&key_buf) {
                    Some(bytes) => deserialize_i64_le(&key_buf, bytes)? + reservation.count as i64,
                    None => reservation.count as i64,
                };
                map.insert(key_buf.clone(), next.to_le_bytes().to_vec());
                result.fill_slots(reservation.first_slot, reservation.count, next as u32);
            }
        }

        for op in batch.ops.iter_mut() {
            match op {
                Operation::AccountId {
                    account_id: account_id_,
                } => {
                    account_id = *account_id_;
                    if has_changes {
                        result.set_current_change_id(account_id, change_group);
                    }
                }
                Operation::Collection {
                    collection: collection_,
                } => {
                    collection = u8::from(*collection_);
                    change_group = collection_.change_group();
                    if has_changes {
                        result.set_current_change_id(account_id, change_group);
                    }
                }
                Operation::DocumentId {
                    document_id: document_id_,
                } => {
                    document_id = document_id_.resolve(result);
                }
                Operation::Value { class, op } => {
                    let subspace = class.subspace(collection);
                    let key = class.serialize(account_id, collection, document_id, 0);
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
                Operation::Index { field, key, set } => {
                    let index_key = IndexKey {
                        account_id,
                        collection,
                        document_id,
                        field: *field,
                        key: key.as_slice(),
                    }
                    .serialize(0);
                    let map = state.subspaces.entry(Subspace::Indexes).or_default();
                    if *set {
                        map.insert(index_key, Vec::new());
                    } else {
                        map.remove(&index_key);
                    }
                }
                Operation::Log { collection, set } => {
                    let log_change_id = result
                        .change_id(account_id, collection.change_group())
                        .unwrap_or_default();
                    debug_assert!(
                        log_change_id != 0,
                        "no change id was allocated for this account"
                    );
                    let log_key = LogKey {
                        account_id,
                        collection: u8::from(*collection),
                        change_id: log_change_id,
                    }
                    .serialize(0);
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
