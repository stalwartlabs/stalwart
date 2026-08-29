/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Batch, BatchBuilder, ChangedCollection, IntoOperations, Operation, QueueNotify, ValueClass,
    ValueOp, assert::ToAssertValue, log::VanishedItem,
};
use crate::{
    Deserialize, Serialize, SerializeInfallible, U32_LEN,
    search::GLOBAL_BUCKET_SHIFT,
    write::{
        AssignedIds, ChangeCounter, CommitPointOffsets, DOCUMENT_ID_SET, LogCollection, LogSet,
        MergeOperation, MergeResult, PendingId, PendingTask, QueueDocumentId, Reservation,
        ReservationClass, SearchIndex, SearchIndexClass, SetValue, SizedSetValue, Slot, SlotRange,
        TaskId, TaskQueueClass,
    },
};
use registry::{
    schema::structs::Task,
    types::{EnumImpl, ObjectImpl},
};
use roaring::RoaringBitmap;
use types::{
    collection::{ChangeGroup, Collection, SyncCollection, VanishedCollection},
    field::FieldType,
    id::Id,
};
use utils::{map::vec_map::VecMap, snowflake::SnowflakeIdGenerator};

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
            next_slot: 0,
            batch_size: 0,
            batch_ops: 0,
            has_assertions: false,
            commit_points: Vec::new(),
            last_archive_hash: None,
            last_index_partition: None,
            has_index_tasks: false,
            has_tasks: false,
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
        self.has_assertions = false;
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
        self.ops.push(Operation::AssertValue {
            class: class.into(),
            assert_value: value.to_assert_value(),
        });
        self.batch_ops += 1;
        self.has_assertions = true;
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

    pub fn merge_document_ids(
        &mut self,
        field: impl FieldType,
        changes: Vec<(PendingId, bool)>,
    ) -> &mut Self {
        self.with_document(DOCUMENT_ID_SET).merge_fnc(
            ValueClass::Property(field.into()),
            move |ids, bytes| {
                let mut document_ids = match bytes {
                    Some(bytes) => RoaringBitmap::deserialize(bytes)?,
                    None => RoaringBitmap::new(),
                };
                let mut has_changes = false;

                for (document_id, do_insert) in &changes {
                    let document_id = document_id.resolve(ids);
                    if *do_insert {
                        has_changes |= document_ids.insert(document_id);
                    } else {
                        has_changes |= document_ids.remove(document_id);
                    }
                }

                if !has_changes {
                    Ok(MergeResult::Skip)
                } else if !document_ids.is_empty() {
                    Ok(MergeResult::Update(document_ids.serialize()?))
                } else {
                    Ok(MergeResult::Delete)
                }
            },
        )
    }

    pub fn add(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
        self.batch_size += class.key_len_hint() + std::mem::size_of::<i64>();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::AtomicAdd(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn add_and_get(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
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
        self.batch_size += class.key_len_hint();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::MergeFnc(MergeOperation(Box::new(fnc))),
        });
        self.batch_ops += 1;
        self
    }

    pub fn set_archive_hash(&mut self, hash: Option<u32>) -> &mut Self {
        self.last_archive_hash = hash;
        self
    }

    pub fn clear(&mut self, class: impl Into<ValueClass>) -> &mut Self {
        let class = class.into();
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
                if changelog.changes.is_empty() && changelog.vanished.is_empty() {
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

                    let set = if changes.has_pending() {
                        LogSet::Pending(Box::new(changes))
                    } else {
                        LogSet::Bytes(changes.serialize(collection.is_prefixed(), &mut scratch))
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

    pub fn add_commit_point(&mut self) -> &mut Self {
        self.serialize_changes();
        self.sort_allocations_for_lock_order();
        self.commit_points.push(CommitPointOffsets {
            ops: self.ops.len(),
            reservations: self.reservations.len(),
            change_accounts: self.change_accounts.len(),
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

    #[inline]
    pub fn is_large_batch(&self) -> bool {
        self.batch_size > 5_000_000 || self.batch_ops > 1000
    }

    pub fn any_op(&mut self, op: Operation) -> &mut Self {
        if let Operation::Value { class, op } = &op {
            self.batch_size += class.key_len_hint();
            if let ValueOp::Set(value) = op {
                self.batch_size += value.len();

                match class {
                    ValueClass::TaskQueue(TaskQueueClass::Due { .. }) => {
                        self.has_tasks = true;
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
        self.sort_allocations_for_lock_order();
        CommitPointIterator {
            commit_points: std::mem::take(&mut self.commit_points),
            commit_point_last: CommitPointOffsets {
                ops: self.ops.len(),
                reservations: self.reservations.len(),
                change_accounts: self.change_accounts.len(),
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
            ops: &mut self.ops[commit_point.offset_start..commit_point.offset_end],
        }
    }

    pub fn queue_notify(&self) -> QueueNotify {
        QueueNotify {
            tasks: self.has_tasks,
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
        self.batch_ops == 0
    }

    pub fn schedule_task(&mut self, task: Task) -> &mut Self {
        self.schedule_task_with_id(SnowflakeIdGenerator::global_id().unwrap_or_default(), task)
    }

    pub fn schedule_task_with_id(&mut self, id: u64, task: Task) -> &mut Self {
        self.push_task(TaskId::Assigned(id), task, None)
    }

    pub fn schedule_document_task(&mut self, task: Task) -> &mut Self {
        let document_id = self
            .current_document_id
            .expect("no document is set for a document task");

        self.push_task(TaskId::Document, task, Some(document_id))
    }

    pub fn schedule_task_with_document(&mut self, task: Task) -> &mut Self {
        let document_id = self
            .current_document_id
            .expect("no document is set for a document task");
        let id = TaskId::Assigned(SnowflakeIdGenerator::global_id().unwrap_or_default());

        self.push_task(id, task, Some(document_id))
    }

    fn push_task(
        &mut self,
        id: TaskId,
        mut task: Task,
        document_id: Option<PendingId>,
    ) -> &mut Self {
        let due = task.due_timestamp();
        let class = task.object_type().to_id();
        self.has_tasks = true;

        let value = match document_id {
            Some(PendingId::Slot(slot)) => SetValue::serializable(PendingTask { task, slot }),
            Some(PendingId::Assigned(document_id)) => {
                task.set_document_id(Id::from(document_id));
                SetValue::fixed(task.to_pickled_vec())
            }
            None => SetValue::fixed(task.to_pickled_vec()),
        };

        self.set(ValueClass::TaskQueue(TaskQueueClass::Task { id }), value)
            .set(
                ValueClass::TaskQueue(TaskQueueClass::Due { id, due }),
                class.serialize(),
            )
    }

    pub fn clear_document_task(&mut self, due: u64) -> &mut Self {
        self.clear(ValueClass::TaskQueue(TaskQueueClass::Task {
            id: TaskId::Document,
        }))
        .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Document,
            due,
        }))
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
                created_at: SnowflakeIdGenerator::global_id_with_sequence_id(0).unwrap_or_default(),
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
                created_at: SnowflakeIdGenerator::global_id_with_sequence_id(0).unwrap_or_default(),
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
                    created_at: SnowflakeIdGenerator::global_id_with_sequence_id(0)
                        .unwrap_or_default(),
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
                };
                self.offset_start = end;
                point
            })
    }
}

impl Batch<'_> {
    pub fn is_atomic(&self) -> bool {
        !self.ops.iter().any(|op| {
            matches!(
                op,
                Operation::AssertValue { .. }
                    | Operation::Value {
                        op: ValueOp::AddAndGet(_),
                        ..
                    }
            )
        })
    }

    pub fn first_account_id(&self) -> Option<u32> {
        self.ops.iter().find_map(|op| match op {
            Operation::AccountId { account_id } => Some(*account_id),
            _ => None,
        })
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}
