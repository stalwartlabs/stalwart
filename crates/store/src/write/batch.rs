/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AccountCounter, Batch, BatchBuilder, ChangedCollection, CommitPriority, IntoOperations,
    Operation, QueueCounter, QueueNotify, ValueClass, ValueOp, assert::ToAssertValue,
    counter::CounterKey, log::VanishedItem,
};
use crate::{
    Deserialize, Shape, Subspace, U32_LEN,
    search::GLOBAL_BUCKET_SHIFT,
    write::{
        AssignedIds, ChangeCounter, CommitPointOffsets, LogCollection, LogSet, MergeOperation,
        MergeResult, PendingId, PendingTask, QueueDocumentId, Reservation, ReservationClass,
        SearchIndex, SearchIndexClass, SetValue, SizedSetValue, Slot, SlotRange, TaskId,
        TaskQueueClass, TaskTypes,
    },
};
use registry::{
    schema::{enums::TaskType, structs::Task},
    types::ObjectImpl,
};
use types::{
    collection::{ChangeGroup, Collection, SyncCollection, VanishedCollection},
    field::FieldType,
    id::Id,
};
use utils::{map::vec_map::VecMap, snowflake::SnowflakeIdGenerator};

const MAX_COMMIT_BYTES: usize = 5_000_000;
const MAX_COMMIT_OPS: usize = 1000;
const MAX_BULK_COMMIT_OPS: usize = 5000;

impl BatchBuilder {
    pub fn new() -> Self {
        Self {
            ops: Vec::with_capacity(32),
            current_account_id: None,
            current_collection: None,
            current_document_id: None,
            changes: Default::default(),
            changed_collections: Default::default(),
            change_accounts: Vec::new(),
            reservations: Vec::new(),
            bounds: Vec::new(),
            counters: Default::default(),
            next_slot: 0,
            batch_size: 0,
            batch_ops: 0,
            commit_points: Vec::new(),
            last_archive_hash: None,
            last_index_partition: None,
            has_index_tasks: false,
            task_types: TaskTypes::default(),
            priority: CommitPriority::Default,
        }
    }

    pub fn with_priority(priority: CommitPriority) -> Self {
        Self {
            priority,
            ..Self::new()
        }
    }

    pub fn with_account_id(&mut self, account_id: u32) -> &mut Self {
        if self
            .current_account_id
            .is_none_or(|current_account_id| current_account_id != account_id)
        {
            self.current_account_id = account_id.into();
            self.ops.push(Operation::AccountId { account_id });
        }
        self
    }

    pub fn with_collection(&mut self, collection: Collection) -> &mut Self {
        let collection_ = Some(collection);
        if collection_ != self.current_collection {
            self.current_collection = collection_;
            self.ops.push(Operation::Collection { collection });
        }
        self
    }

    pub fn with_document(&mut self, document_id: u32) -> &mut Self {
        self.with_pending_document(PendingId::Assigned(document_id))
    }

    pub fn create_document(&mut self, slot: Slot) -> &mut Self {
        self.with_pending_document(PendingId::Slot(slot))
    }

    pub fn with_pending_document(&mut self, document_id: PendingId) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self.current_document_id = Some(document_id);
        self
    }

    pub fn reserve_document_id(&mut self, account_id: u32, collection: Collection) -> Slot {
        self.reserve(ReservationClass::DocumentId {
            account_id,
            collection,
        })
    }

    pub fn reserve_document_ids(
        &mut self,
        account_id: u32,
        collection: Collection,
        count: u32,
    ) -> SlotRange {
        SlotRange::new(
            self.reserve_many(
                ReservationClass::DocumentId {
                    account_id,
                    collection,
                },
                count,
            ),
            count,
        )
    }

    pub fn reserve_uid(&mut self, account_id: u32, mailbox_id: u32) -> Slot {
        self.reserve(ReservationClass::Uid {
            account_id,
            mailbox_id,
        })
    }

    pub fn reserve_uids(
        &mut self,
        account_id: u32,
        mailbox_ids: impl IntoIterator<Item = u32>,
    ) -> SlotRange {
        let first_slot = Slot::new(self.next_slot);
        let mut count = 0;
        for mailbox_id in mailbox_ids {
            self.reserve(ReservationClass::Uid {
                account_id,
                mailbox_id,
            });
            count += 1;
        }

        SlotRange::new(first_slot, count)
    }

    fn reserve(&mut self, class: ReservationClass) -> Slot {
        let next_slot = self.next_slot;
        let reservations_start = self.reservations_start();
        if self.reservations.len() > reservations_start
            && let Some(last) = self.reservations.last_mut()
            && last.class == class
            && last.first_slot.index() + last.count as usize == next_slot as usize
        {
            last.count += 1;
            self.next_slot += 1;
            return Slot::new(next_slot);
        }

        self.reserve_many(class, 1)
    }

    fn reserve_many(&mut self, class: ReservationClass, count: u32) -> Slot {
        let first_slot = Slot::new(self.next_slot);
        self.next_slot = self
            .next_slot
            .checked_add(count)
            .expect("too many reserved ids");
        self.reservations.push(Reservation {
            class,
            first_slot,
            count,
        });
        first_slot
    }

    pub fn assert_value(
        &mut self,
        class: impl Into<ValueClass>,
        value: impl ToAssertValue,
    ) -> &mut Self {
        let class = class.into();
        self.settle_counter(&class, true);
        self.ops.push(Operation::AssertValue {
            class,
            assert_value: value.to_assert_value(),
        });
        self.batch_ops += 1;
        self
    }

    pub fn index(&mut self, field: impl FieldType, value: impl Into<Vec<u8>>) -> &mut Self {
        let field = field.into();
        let value = value.into();
        let value_len = value.len();

        self.ops.push(Operation::Index {
            field,
            key: value,
            set: true,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    pub fn unindex(&mut self, field: impl FieldType, value: impl Into<Vec<u8>>) -> &mut Self {
        let field = field.into();
        let value = value.into();
        let value_len = value.len();

        self.ops.push(Operation::Index {
            field,
            key: value,
            set: false,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    #[inline(always)]
    pub fn tag(&mut self, field: impl FieldType) -> &mut Self {
        self.index(field, vec![])
    }

    #[inline(always)]
    pub fn untag(&mut self, field: impl FieldType) -> &mut Self {
        self.unindex(field, vec![])
    }

    pub fn add(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
        if let Some(key) = CounterKey::new(&class, self.current_account_id) {
            if self.counters.add(key, value) {
                self.batch_size += class.key_len_hint() + std::mem::size_of::<i64>();
                self.batch_ops += 1;
            }
            return self;
        }

        self.batch_size += class.key_len_hint() + std::mem::size_of::<i64>();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::AtomicAdd(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn limit_counter(&mut self, counter: AccountCounter, max: u64) -> &mut Self {
        debug_assert!(
            self.current_account_id.is_some(),
            "a counter bound needs an account"
        );
        self.counters.limit(
            CounterKey::account(self.current_account_id, counter),
            i64::try_from(max).unwrap_or(i64::MAX),
        );
        self
    }

    pub fn limit_queue_counter(&mut self, counter: QueueCounter, max: u64) -> &mut Self {
        self.counters.limit(
            CounterKey::Queue(counter),
            i64::try_from(max).unwrap_or(i64::MAX),
        );
        self
    }

    pub fn add_and_get(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
        self.settle_counter(&class, true);
        self.batch_size += class.key_len_hint() + (std::mem::size_of::<i64>() * 2);
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::AddAndGet(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn set(
        &mut self,
        class: impl Into<ValueClass>,
        value: impl Into<SizedSetValue>,
    ) -> &mut Self {
        let class = class.into();
        self.settle_counter(&class, false);
        let SizedSetValue { value, size_hint } = value.into();
        self.batch_size += class.key_len_hint() + size_hint;
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::Set(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn merge_fnc(
        &mut self,
        class: impl Into<ValueClass>,
        fnc: impl Fn(&AssignedIds, Option<&[u8]>) -> trc::Result<MergeResult> + Send + Sync + 'static,
    ) -> &mut Self {
        let class = class.into();
        self.settle_counter(&class, true);
        self.batch_size += class.key_len_hint();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::MergeFnc(MergeOperation(Box::new(fnc))),
        });
        self.batch_ops += 1;
        self
    }

    pub fn clear_if_equals<T>(&mut self, class: impl Into<ValueClass>, value: T) -> &mut Self
    where
        T: Deserialize + PartialEq + Send + Sync + 'static,
    {
        self.merge_fnc(class, move |_, bytes| match bytes {
            Some(bytes) if T::deserialize(bytes)? == value => Ok(MergeResult::Delete),
            _ => Ok(MergeResult::Skip),
        })
    }

    pub fn set_archive_hash(&mut self, hash: Option<u32>) -> &mut Self {
        self.last_archive_hash = hash;
        self
    }

    pub fn clear(&mut self, class: impl Into<ValueClass>) -> &mut Self {
        let class = class.into();
        if let Some(key) = CounterKey::new(&class, self.current_account_id) {
            if self.counters.reset(key) {
                self.batch_size += class.key_len_hint();
                self.batch_ops += 1;
            }
            return self;
        }
        self.settle_counter(&class, false);
        self.batch_size += class.key_len_hint();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::Clear,
        });
        self.batch_ops += 1;
        self
    }

    pub fn acl_grant(&mut self, grant_account_id: u32, op: Vec<u8>) -> &mut Self {
        self.batch_size += (U32_LEN * 3) + op.len();
        self.ops.push(Operation::Value {
            class: ValueClass::Acl(grant_account_id),
            op: ValueOp::Set(SetValue::Fixed(op)),
        });
        self.batch_ops += 1;
        self
    }

    pub fn acl_revoke(&mut self, grant_account_id: u32) -> &mut Self {
        self.batch_size += U32_LEN * 3;
        self.ops.push(Operation::Value {
            class: ValueClass::Acl(grant_account_id),
            op: ValueOp::Clear,
        });
        self.batch_ops += 1;
        self
    }

    pub fn log_item_insert(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_insert(
                collection,
                prefix,
                document_id,
            );
        }
        self
    }

    pub fn log_item_update(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_update(
                collection,
                prefix,
                document_id,
            );
        }
        self
    }

    pub fn log_item_delete(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_delete(
                collection,
                prefix,
                document_id,
            );
        }
        self
    }

    pub fn log_container_insert(&mut self, collection: SyncCollection) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_insert(collection, document_id);
        }
        self
    }

    pub fn log_container_update(&mut self, collection: SyncCollection) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_update(collection, document_id);
        }
        self
    }

    pub fn log_container_delete(&mut self, collection: SyncCollection) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_delete(collection, document_id);
        }
        self
    }

    pub fn log_container_property_change(
        &mut self,
        collection: SyncCollection,
        document_id: PendingId,
    ) -> &mut Self {
        if let Some(account_id) = self.current_account_id {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_property_update(collection, document_id);
        }
        self
    }

    pub fn log_container_metadata(&mut self, collection: SyncCollection) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_metadata(collection, document_id);
        }
        self
    }

    pub fn log_item_metadata(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_item_metadata(collection, prefix, document_id);
        }
        self
    }

    pub fn log_private_container_metadata(
        &mut self,
        collection: SyncCollection,
        viewer: u32,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_private_container_metadata(collection, viewer, document_id);
        }
        self
    }

    pub fn log_private_item_metadata(
        &mut self,
        collection: SyncCollection,
        viewer: u32,
        prefix: Option<PendingId>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_private_item_metadata(collection, viewer, prefix, document_id);
        }
        self
    }

    pub fn log_vanished_item(
        &mut self,
        collection: VanishedCollection,
        item: impl Into<VanishedItem>,
    ) -> &mut Self {
        if let Some(account_id) = self.current_account_id {
            let item = item.into();
            self.batch_size += item.serialized_size();
            self.changes
                .get_mut_or_insert(account_id)
                .log_vanished_item(collection, item);
        }
        self
    }

    pub fn log_share_notification(
        &mut self,
        notification_id: u64,
        notify_account_id: u32,
        value: impl Into<SizedSetValue>,
    ) -> &mut Self {
        self.changed_collections
            .get_mut_or_insert(notify_account_id)
            .share_notification_id = Some(notification_id);
        self.set(
            ValueClass::ShareNotification {
                notification_id,
                notify_account_id,
            },
            value,
        )
    }

    fn sort_allocations_for_lock_order(&mut self) {
        let reservations_start = self.reservations_start();
        self.reservations[reservations_start..].sort_unstable_by_key(|reservation| {
            (reservation.class.sort_key(), reservation.first_slot)
        });

        let change_accounts_start = self.change_accounts_start();
        self.change_accounts[change_accounts_start..]
            .sort_unstable_by_key(|entry| (entry.account_id, entry.group));
    }

    fn serialize_changes(&mut self) {
        if !self.changes.is_empty() {
            for (account_id, changelog) in std::mem::take(&mut self.changes) {
                if changelog.changes.is_empty()
                    && changelog.vanished.is_empty()
                    && changelog.private.is_empty()
                {
                    continue;
                }
                self.with_account_id(account_id);

                // Serialize changes
                let mut scratch = Vec::new();
                for (collection, changes) in changelog.changes.into_iter() {
                    let cc = self.changed_collections.get_mut_or_insert(account_id);
                    if changes.has_container_changes() {
                        cc.changed_containers.insert(collection);
                    }
                    if changes.has_item_changes() {
                        cc.changed_items.insert(collection);
                    }
                    self.register_change_group(account_id, collection.change_group());

                    let set = match changes.serialize(collection.is_prefixed(), &mut scratch) {
                        Some(bytes) => LogSet::Bytes(bytes),
                        None => LogSet::Pending(Box::new(changes)),
                    };
                    self.ops.push(Operation::Log {
                        collection: LogCollection::Sync(collection),
                        set,
                    });
                }

                // Serialize vanished items
                for (collection, vanished) in changelog.vanished.into_iter() {
                    self.register_change_group(account_id, collection.change_group());
                    self.ops.push(Operation::Log {
                        collection: LogCollection::Vanished(collection),
                        set: LogSet::Bytes(vanished.serialize(collection.is_named(), &mut scratch)),
                    });
                }

                for (log, changes) in changelog.private.into_iter() {
                    self.register_change_group(account_id, log.collection.change_group());
                    let set = match changes.serialize(log.collection.is_prefixed(), &mut scratch) {
                        Some(bytes) => LogSet::Bytes(bytes),
                        None => LogSet::Pending(Box::new(changes)),
                    };
                    self.ops.push(Operation::Log {
                        collection: LogCollection::Private {
                            collection: log.collection,
                            viewer: log.viewer,
                        },
                        set,
                    });
                }
            }
        }
    }

    #[inline(always)]
    fn change_accounts_start(&self) -> usize {
        self.commit_points
            .last()
            .map_or(0, |commit_point| commit_point.change_accounts)
    }

    #[inline(always)]
    fn reservations_start(&self) -> usize {
        self.commit_points
            .last()
            .map_or(0, |commit_point| commit_point.reservations)
    }

    fn register_change_group(&mut self, account_id: u32, group: ChangeGroup) {
        let entry = ChangeCounter { account_id, group };
        if !self.change_accounts[self.change_accounts_start()..].contains(&entry) {
            self.change_accounts.push(entry);
        }
    }

    #[inline]
    pub fn commit_point(&mut self) -> &mut Self {
        if self.is_large_batch() {
            self.add_commit_point()
        } else {
            self
        }
    }

    #[inline]
    pub fn bulk_commit_point(&mut self) -> &mut Self {
        if self.is_large_bulk_batch() {
            self.add_commit_point()
        } else {
            self
        }
    }

    pub fn add_commit_point(&mut self) -> &mut Self {
        self.serialize_changes();
        self.flush_counters();
        self.sort_allocations_for_lock_order();
        self.commit_points.push(CommitPointOffsets {
            ops: self.ops.len(),
            reservations: self.reservations.len(),
            change_accounts: self.change_accounts.len(),
            bounds: self.bounds.len(),
        });
        self.batch_ops = 0;
        self.batch_size = 0;
        self.last_index_partition = None;
        if let Some(account_id) = self.current_account_id {
            self.ops.push(Operation::AccountId { account_id });
        }
        if let Some(collection) = self.current_collection {
            self.ops.push(Operation::Collection { collection });
        }
        self
    }

    pub fn has_commit_points(&self) -> bool {
        !self.commit_points.is_empty()
    }

    pub fn commit_point_count(&self) -> usize {
        self.commit_points.len()
    }

    #[inline]
    pub fn is_large_batch(&self) -> bool {
        self.batch_size > MAX_COMMIT_BYTES || self.batch_ops > MAX_COMMIT_OPS
    }

    #[inline]
    pub fn is_large_bulk_batch(&self) -> bool {
        self.batch_size > MAX_COMMIT_BYTES || self.batch_ops > MAX_BULK_COMMIT_OPS
    }

    fn settle_counter(&mut self, class: &ValueClass, keep_pending: bool) {
        if !self.counters.is_empty()
            && let Some(key) = CounterKey::new(class, self.current_account_id)
        {
            let (reset, delta) = self.counters.settle(key);
            if keep_pending && reset {
                self.ops.push(Operation::Value {
                    class: class.clone(),
                    op: ValueOp::Clear,
                });
            }
            if keep_pending && delta != 0 {
                self.ops.push(Operation::Value {
                    class: class.clone(),
                    op: ValueOp::AtomicAdd(delta),
                });
            }
        }
    }

    fn flush_counters(&mut self) {
        if !self.counters.is_empty() {
            self.counters
                .flush(self.current_account_id, &mut self.ops, &mut self.bounds);
        }
    }

    pub fn any_op(&mut self, op: Operation) -> &mut Self {
        match op {
            Operation::Value {
                class,
                op: ValueOp::AtomicAdd(value),
            } => return self.add(class, value),
            Operation::Value {
                class,
                op: ValueOp::Clear,
            } if CounterKey::new(&class, self.current_account_id).is_some() => {
                return self.clear(class);
            }
            Operation::Value { ref class, ref op } => {
                self.settle_counter(class, !matches!(op, ValueOp::Set(_) | ValueOp::Clear));
            }
            Operation::AssertValue { ref class, .. } => self.settle_counter(class, true),
            Operation::AccountId { account_id } => self.current_account_id = Some(account_id),
            Operation::Collection { collection } => self.current_collection = Some(collection),
            Operation::DocumentId { document_id } => self.current_document_id = Some(document_id),
            Operation::ClearRange {
                subspace,
                ref from,
                ref to,
            } => {
                if matches!(subspace.shape(), Shape::Counter) && !self.counters.is_empty() {
                    self.counters.clear_range(subspace, from, to);
                }
                self.batch_size += from.len() + to.len();
            }
            Operation::Index { .. } | Operation::Log { .. } => {}
        }

        if let Operation::Value { class, op } = &op {
            self.batch_size += class.key_len_hint();
            if let ValueOp::Set(value) = op {
                self.batch_size += value.len();

                match class {
                    ValueClass::TaskQueue(TaskQueueClass::Due { typ, due, .. })
                        if *due != u64::MAX =>
                    {
                        self.task_types.insert(*typ);
                    }
                    ValueClass::SearchIndex(SearchIndexClass::Queue { .. }) => {
                        self.has_index_tasks = true;
                    }
                    _ => {}
                }
            }
        }

        self.ops.push(op);
        self.batch_ops += 1;
        self
    }

    pub fn clear_range(&mut self, subspace: Subspace, from: Vec<u8>, to: Vec<u8>) -> &mut Self {
        self.any_op(Operation::ClearRange { subspace, from, to })
    }

    pub fn custom(&mut self, value: impl IntoOperations) -> trc::Result<&mut Self> {
        value.build(self)?;
        Ok(self)
    }

    pub fn last_account_id(&self) -> Option<u32> {
        self.current_account_id
    }

    pub fn last_collection(&self) -> Option<Collection> {
        self.current_collection
    }

    pub fn last_document_id(&self) -> Option<PendingId> {
        self.current_document_id
    }

    pub fn last_archive_hash(&self) -> Option<u32> {
        self.last_archive_hash
    }

    pub fn commit_points(&mut self) -> CommitPointIterator {
        self.serialize_changes();
        self.flush_counters();
        self.sort_allocations_for_lock_order();
        CommitPointIterator {
            commit_points: std::mem::take(&mut self.commit_points),
            commit_point_last: CommitPointOffsets {
                ops: self.ops.len(),
                reservations: self.reservations.len(),
                change_accounts: self.change_accounts.len(),
                bounds: self.bounds.len(),
            },
            offset_start: CommitPointOffsets::default(),
        }
    }

    pub fn build_one(&mut self, commit_point: CommitPoint) -> Batch<'_> {
        Batch {
            change_accounts: &self.change_accounts
                [commit_point.change_account_start..commit_point.change_account_end],
            reservations: &self.reservations
                [commit_point.reservation_start..commit_point.reservation_end],
            bounds: &self.bounds[commit_point.bound_start..commit_point.bound_end],
            ops: &mut self.ops[commit_point.offset_start..commit_point.offset_end],
            priority: self.priority,
        }
    }

    pub fn queue_notify(&self) -> QueueNotify {
        QueueNotify {
            task_types: self.task_types,
            search_index: self.has_index_tasks,
        }
    }

    pub fn changes(self) -> Option<VecMap<u32, ChangedCollection>> {
        if self.has_changes() {
            Some(self.changed_collections)
        } else {
            None
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.changed_collections.is_empty()
    }

    pub fn ops(&self) -> &[Operation] {
        self.ops.as_slice()
    }

    pub fn len(&self) -> usize {
        self.batch_size
    }

    pub fn is_empty(&self) -> bool {
        self.batch_ops == 0 && self.commit_points.is_empty() && self.changes.is_empty()
    }

    pub fn schedule_task(&mut self, task: Task) -> &mut Self {
        match task.singleton_key() {
            Some((discriminant, key)) => self.schedule_singleton_task(discriminant, key, task),
            None => self
                .schedule_task_with_id(SnowflakeIdGenerator::global_id().unwrap_or_default(), task),
        }
    }

    pub fn schedule_task_with_id(&mut self, id: u64, task: Task) -> &mut Self {
        self.push_task(TaskId::Assigned(id), task, None)
    }

    pub fn schedule_document_task(&mut self, id: TaskId, task: Task) -> trc::Result<&mut Self> {
        let document_id = self.document_id_for_task()?;

        Ok(self.push_task(id, task, Some(document_id)))
    }

    pub fn schedule_task_with_document(&mut self, task: Task) -> trc::Result<&mut Self> {
        let document_id = self.document_id_for_task()?;
        let id = TaskId::Assigned(SnowflakeIdGenerator::global_id().unwrap_or_default());

        Ok(self.push_task(id, task, Some(document_id)))
    }

    fn document_id_for_task(&self) -> trc::Result<PendingId> {
        self.current_document_id.ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No document is set for a document task.")
        })
    }

    pub fn schedule_singleton_task(
        &mut self,
        discriminant: u16,
        key: u64,
        task: Task,
    ) -> &mut Self {
        let typ = task.object_type();
        let id = TaskId::Assigned(TaskId::singleton(typ, discriminant, key));
        self.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id,
            typ,
            due: u64::MAX,
        }))
        .push_task(id, task, None)
    }

    fn push_task(
        &mut self,
        id: TaskId,
        mut task: Task,
        document_id: Option<PendingId>,
    ) -> &mut Self {
        let due = task.due_timestamp();
        let typ = task.object_type();
        let marker = TaskQueueClass::due_marker(task.status());

        let value = match document_id {
            Some(PendingId::Slot(slot)) => SetValue::serializable(PendingTask { task, slot }),
            Some(PendingId::Assigned(document_id)) => {
                task.set_document_id(Id::from(document_id));
                SetValue::fixed(task.to_pickled_vec())
            }
            None => SetValue::fixed(task.to_pickled_vec()),
        };

        self.set(ValueClass::TaskQueue(TaskQueueClass::Task { id }), value)
            .set_task_due_marked(id, typ, due, marker)
    }

    pub fn set_task_due(&mut self, id: TaskId, typ: TaskType, due: u64) -> &mut Self {
        self.set_task_due_marked(id, typ, due, None)
    }

    pub fn set_task_due_marked(
        &mut self,
        id: TaskId,
        typ: TaskType,
        due: u64,
        marker: Option<u8>,
    ) -> &mut Self {
        if due != u64::MAX {
            self.task_types.insert(typ);
        }
        self.set(
            ValueClass::TaskQueue(TaskQueueClass::Due { id, typ, due }),
            marker.map_or_else(Vec::new, |marker| vec![marker]),
        )
    }

    pub fn clear_document_task(&mut self, id: TaskId, typ: TaskType, due: u64) -> &mut Self {
        self.clear(ValueClass::TaskQueue(TaskQueueClass::Task { id }))
            .clear(ValueClass::TaskQueue(TaskQueueClass::Due { id, typ, due }))
    }

    pub fn queue_document_index(
        &mut self,
        index: SearchIndex,
        account_id: u32,
        document_id: impl Into<QueueDocumentId>,
    ) -> &mut Self {
        let document_id = document_id.into();
        self.queue_index_task(index, account_id).set(
            ValueClass::SearchIndex(SearchIndexClass::Queue {
                index,
                id_prefix: account_id,
                id_suffix: document_id,
                created_at: SnowflakeIdGenerator::global_id().unwrap_or_default(),
            }),
            vec![1u8],
        )
    }

    pub fn queue_document_unindex(
        &mut self,
        index: SearchIndex,
        account_id: u32,
        document_id: impl Into<QueueDocumentId>,
    ) -> &mut Self {
        let document_id = document_id.into();
        self.queue_index_task(index, account_id).set(
            ValueClass::SearchIndex(SearchIndexClass::Queue {
                index,
                id_prefix: account_id,
                id_suffix: document_id,
                created_at: SnowflakeIdGenerator::global_id().unwrap_or_default(),
            }),
            vec![0u8],
        )
    }

    pub fn queue_trace_index(&mut self, id: u64) -> &mut Self {
        self.queue_index_task(SearchIndex::Tracing, (id >> GLOBAL_BUCKET_SHIFT) as u32)
            .set(
                ValueClass::SearchIndex(SearchIndexClass::Queue {
                    index: SearchIndex::Tracing,
                    id_prefix: (id >> 32) as u32,
                    id_suffix: QueueDocumentId::Assigned(id as u32),
                    created_at: SnowflakeIdGenerator::global_id().unwrap_or_default(),
                }),
                vec![1u8],
            )
    }

    fn queue_index_task(&mut self, index: SearchIndex, partition: u32) -> &mut Self {
        self.has_index_tasks = true;
        if self.last_index_partition != Some((index, partition)) {
            self.last_index_partition = Some((index, partition));
            self.set(
                ValueClass::SearchIndex(SearchIndexClass::QueueIndex { index, partition }),
                vec![],
            );
        }

        self
    }
}

pub struct CommitPointIterator {
    commit_points: Vec<CommitPointOffsets>,
    commit_point_last: CommitPointOffsets,
    offset_start: CommitPointOffsets,
}

pub struct CommitPoint {
    pub offset_start: usize,
    pub offset_end: usize,
    pub reservation_start: usize,
    pub reservation_end: usize,
    pub change_account_start: usize,
    pub change_account_end: usize,
    pub bound_start: usize,
    pub bound_end: usize,
}

impl CommitPointIterator {
    pub fn iter(&mut self) -> impl Iterator<Item = CommitPoint> {
        self.commit_points
            .iter()
            .copied()
            .chain([self.commit_point_last])
            .map(|end| {
                let point = CommitPoint {
                    offset_start: self.offset_start.ops,
                    offset_end: end.ops,
                    reservation_start: self.offset_start.reservations,
                    reservation_end: end.reservations,
                    change_account_start: self.offset_start.change_accounts,
                    change_account_end: end.change_accounts,
                    bound_start: self.offset_start.bounds,
                    bound_end: end.bounds,
                };
                self.offset_start = end;
                point
            })
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/write/batch/tests.rs"]
mod tests;
