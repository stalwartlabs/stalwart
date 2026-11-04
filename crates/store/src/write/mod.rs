/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::assert::AssertValue;
use crate::{
    ChangeLogKey, IndexKey, Key, LogKey, PrivateLogKey, Subspace, U32_LEN, U64_LEN,
    backend::MAX_TOKEN_LENGTH,
};
use log::ChangeLogBuilder;
use metadata::MetadataClass;
use nlp::tokenizers::word::WordTokenizer;
use registry::{
    schema::{
        enums::{StorageQuota, TaskType},
        structs::Task,
    },
    types::{EnumImpl, ObjectImpl},
};
use std::{borrow::Cow, collections::HashSet, hash::Hash, time::SystemTime};
use tinyvec::TinyVec;
use types::{
    blob_hash::BlobHash,
    collection::{ChangeGroup, Collection, SyncCollection, VanishedCollection},
    field::{
        CalendarEventField, CalendarNotificationField, ContactField, EmailField,
        EmailSubmissionField, Field, MailboxField, PrincipalField, SieveField,
    },
    id::Id,
};
use utils::{
    cheeky_hash::CheekyHash,
    hash128::Hash128,
    map::{bitmap::Bitmap, vec_map::VecMap},
};
use xxhash_rust::xxh3::xxh3_64;

pub mod assert;
pub mod batch;
pub mod bitpack;
pub mod blob;
pub mod blob_codec;
pub mod compress;
pub mod counter;
pub mod key;
pub mod lazybitmap;
pub mod log;
pub mod metadata;
pub mod serialize;

pub use compress::{ArchiveCompression, Compression, Dictionary};
pub use counter::{AccountCounter, CounterBound, QueueCounter};

#[derive(Debug, Clone)]
pub struct Archive<T> {
    pub inner: T,
    pub version: ArchiveVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveVersion {
    Versioned { change_id: u64, hash: u32 },
    Hashed { hash: u32 },
    Unversioned,
}

pub type ArchiveBytes = Vec<u8>;

const _: () = assert!(std::mem::size_of::<rkyv::primitive::FixedUsize>() == 4);
const _: () = assert!(std::mem::align_of::<rkyv::primitive::ArchivedU64>() == 1);
const _: () = assert!(std::mem::align_of::<rkyv::string::ArchivedString>() == 1);
const _: () = assert!(std::mem::size_of::<ValueClass>() <= 48);
const _: () = assert!(std::mem::size_of::<Operation>() <= 88);

pub struct Archiver<T>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                Vec<u8>,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    pub inner: T,
    pub flags: u8,
    pub compression: Compression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct Slot(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SlotRange {
    first: Slot,
    count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingId {
    Assigned(u32),
    Slot(Slot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChangeCounter {
    pub account_id: u32,
    pub group: ChangeGroup,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ChangeId {
    pub counter: ChangeCounter,
    pub change_id: u64,
}

#[derive(Debug, Default)]
pub struct AssignedIds {
    slots: TinyVec<[u32; 8]>,
    change_ids: TinyVec<[ChangeId; 2]>,
    counter: Option<i64>,
    archive_hash: Option<u32>,
    current_change_id: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommitPointOffsets {
    pub ops: usize,
    pub reservations: usize,
    pub change_accounts: usize,
    pub bounds: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct AssignedIdsMark {
    slots: usize,
    change_ids: usize,
    counter: Option<i64>,
    archive_hash: Option<u32>,
}

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation",
    feature = "sqlite"
))]
pub(crate) use commit_limits::{MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME};

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation",
    feature = "sqlite"
))]
pub(crate) use commit_limits::commit_backoff;

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation"
))]
pub(crate) use commit_limits::exhausted;

#[cfg(all(
    stalwart_tests,
    any(
        feature = "rocks",
        feature = "postgres",
        feature = "mysql",
        feature = "foundation",
        feature = "sqlite"
    )
))]
pub(crate) use commit_limits::record_retry;

#[cfg(any(feature = "postgres", feature = "mysql"))]
pub(crate) use commit_limits::{ChunkPlan, ChunkedRetry, backoff};

#[cfg(any(feature = "postgres", feature = "mysql"))]
mod new_key;

#[cfg(any(feature = "postgres", feature = "mysql"))]
pub(crate) use new_key::{NewKeyAsserts, insert_follows};

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation",
    feature = "sqlite"
))]
#[cfg_attr(stalwart_tests, path = ".")]
mod commit_limits {
    #[cfg(any(feature = "postgres", feature = "mysql"))]
    use crate::{Fetch, ITERATE_BATCH_GROWTH};
    use rand::RngExt;
    use std::time::Duration;

    const PRODUCTION_MAX_COMMIT_ATTEMPTS: u32 = 24;

    #[cfg(not(stalwart_tests))]
    pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = PRODUCTION_MAX_COMMIT_ATTEMPTS;
    #[cfg(not(stalwart_tests))]
    pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(10);

    #[cfg(stalwart_tests)]
    pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 1000;
    #[cfg(stalwart_tests)]
    pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(3600);

    const MIN_COMMIT_BACKOFF_US: u64 = 250;
    const MAX_COMMIT_BACKOFF_US: u64 = 1_000_000;
    const MAX_COMMIT_BACKOFF_SHIFT: u32 = 12;

    pub(crate) fn commit_backoff(attempt: u32) -> Duration {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_commit_retry();

        let ceiling = (MIN_COMMIT_BACKOFF_US << attempt.min(MAX_COMMIT_BACKOFF_SHIFT))
            .min(MAX_COMMIT_BACKOFF_US);

        Duration::from_micros(rand::rng().random_range(0..=ceiling))
    }

    #[cfg(stalwart_tests)]
    #[rustfmt::skip]
    #[path = "../../../../../stalwart-tests/unit/store/src/write/commit_limits/test_support.rs"]
    mod test_support;

    #[cfg(stalwart_tests)]
    pub(crate) use test_support::record_retry;

    #[cfg(any(
        feature = "rocks",
        feature = "postgres",
        feature = "mysql",
        feature = "foundation"
    ))]
    pub(crate) fn exhausted(err: trc::Error, retry_count: u32) -> trc::Error {
        err.ctx(trc::Key::Attempt, retry_count + 1)
    }

    #[cfg(any(feature = "postgres", feature = "mysql"))]
    pub(crate) struct ChunkedRetry {
        chunk_size: Option<usize>,
        first_chunk_size: usize,
        min_chunk_size: usize,
        retry_count: u32,
    }

    #[cfg(any(feature = "postgres", feature = "mysql"))]
    impl ChunkedRetry {
        pub(crate) fn bounded(first_chunk_size: usize, min_chunk_size: usize) -> Self {
            Self {
                chunk_size: Some(first_chunk_size),
                first_chunk_size,
                min_chunk_size,
                retry_count: 0,
            }
        }

        pub(crate) fn chunk_size(&self) -> Option<usize> {
            self.chunk_size
        }

        pub(crate) fn progressed(&mut self) {
            self.retry_count = 0;
        }

        pub(crate) async fn degrade(&mut self) -> bool {
            match self.chunk_size {
                None => {
                    self.chunk_size = Some(self.first_chunk_size);
                    true
                }
                Some(chunk_size) if chunk_size > self.min_chunk_size => {
                    self.chunk_size = Some((chunk_size / 2).max(self.min_chunk_size));
                    true
                }
                Some(_) => backoff(&mut self.retry_count).await,
            }
        }
    }

    #[cfg(any(feature = "postgres", feature = "mysql"))]
    pub(crate) async fn backoff(attempt: &mut u32) -> bool {
        if *attempt < MAX_COMMIT_ATTEMPTS {
            tokio::time::sleep(commit_backoff(*attempt)).await;
            *attempt += 1;
            true
        } else {
            false
        }
    }

    #[cfg(any(feature = "postgres", feature = "mysql"))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum ChunkPlan {
        Unbounded,
        Growing { next: u32 },
        Fixed { next: u32 },
        Capped { remaining: u32, next: u32 },
    }

    #[cfg(any(feature = "postgres", feature = "mysql"))]
    impl ChunkPlan {
        pub(crate) fn new(fetch: Fetch) -> Self {
            match fetch {
                Fetch::All => ChunkPlan::Unbounded,
                Fetch::Expect(rows) => ChunkPlan::Growing {
                    next: rows.saturating_add(1),
                },
                Fetch::Limit(rows) => ChunkPlan::Capped {
                    remaining: rows,
                    next: rows,
                },
            }
        }

        pub(crate) fn limit(self, resuming: bool) -> Option<u32> {
            let rows = match self {
                ChunkPlan::Unbounded => return None,
                ChunkPlan::Growing { next } | ChunkPlan::Fixed { next } => next,
                ChunkPlan::Capped { remaining, next } => remaining.min(next),
            };
            Some(rows.saturating_add(u32::from(resuming)))
        }

        pub(crate) fn consume_row(&mut self) -> bool {
            match self {
                ChunkPlan::Capped { remaining, .. } => {
                    *remaining = remaining.saturating_sub(1);
                    *remaining > 0
                }
                _ => true,
            }
        }

        pub(crate) fn grow(&mut self) {
            if let ChunkPlan::Growing { next } = self {
                *next = next.saturating_mul(ITERATE_BATCH_GROWTH);
            }
        }

        fn shrink(&mut self, first: u32, min: u32) -> bool {
            match *self {
                ChunkPlan::Unbounded => {
                    *self = ChunkPlan::Fixed { next: first };
                    true
                }
                ChunkPlan::Growing { next } | ChunkPlan::Fixed { next } => {
                    *self = ChunkPlan::Fixed {
                        next: Self::halve(next, first, min),
                    };
                    next > min
                }
                ChunkPlan::Capped { remaining, next } => {
                    let current = remaining.min(next);
                    *self = ChunkPlan::Capped {
                        remaining,
                        next: Self::halve(current, first, min),
                    };
                    current > min
                }
            }
        }

        fn halve(current: u32, first: u32, min: u32) -> u32 {
            (current / 2).min(first).max(min).min(current)
        }

        pub(crate) async fn degrade(
            &mut self,
            first: usize,
            min: usize,
            attempt: &mut u32,
        ) -> bool {
            self.shrink(
                u32::try_from(first).unwrap_or(u32::MAX),
                u32::try_from(min).unwrap_or(u32::MAX),
            ) || backoff(attempt).await
        }
    }
    #[cfg(all(test, stalwart_tests, any(feature = "postgres", feature = "mysql")))]
    #[rustfmt::skip]
    #[path = "../../../../../stalwart-tests/unit/store/src/write/commit_limits/tests.rs"]
    mod tests;
}

const UNAVAILABLE_RETRY_AFTER: u64 = 1;
const EXHAUSTED_RETRY_AFTER: u64 = 5;

pub fn unavailable_retry_after(err: &trc::Error) -> Option<u64> {
    if !matches!(
        err.event_type(),
        trc::EventType::Store(trc::StoreEvent::FoundationdbError)
    ) {
        return None;
    }

    match err.value_as_uint(trc::Key::Code)? {
        1007 | 1009 | 1020 | 1021 | 1037 | 1038 | 1039 | 1042 | 1051 | 1078 | 1213 | 1223
        | 1235 | 1242 => Some(if err.value(trc::Key::Attempt).is_some() {
            EXHAUSTED_RETRY_AFTER
        } else {
            UNAVAILABLE_RETRY_AFTER
        }),
        _ => None,
    }
}

pub fn is_commit_contention(err: &trc::Error) -> bool {
    matches!(
        err.event_type(),
        trc::EventType::Store(
            trc::StoreEvent::FoundationdbError
                | trc::StoreEvent::RocksdbError
                | trc::StoreEvent::PostgresqlError
                | trc::StoreEvent::MysqlError
        )
    ) && err.value(trc::Key::Attempt).is_some()
}

#[cfg(all(
    test,
    stalwart_tests,
    any(
        feature = "rocks",
        feature = "postgres",
        feature = "mysql",
        feature = "foundation"
    )
))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/write/contention_tests.rs"]
mod contention_tests;

#[derive(Debug)]
pub struct Batch<'x> {
    pub(crate) change_accounts: &'x [ChangeCounter],
    pub(crate) reservations: &'x [Reservation],
    pub(crate) bounds: &'x [CounterBound],
    pub(crate) ops: &'x mut [Operation],
    #[cfg_attr(not(feature = "foundation"), allow(dead_code))]
    pub(crate) priority: CommitPriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitPriority {
    Default,
    Background,
}

#[derive(Debug, Clone, Copy)]
pub struct Reservation {
    pub class: ReservationClass,
    pub first_slot: Slot,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationClass {
    DocumentId {
        account_id: u32,
        collection: Collection,
    },
    Uid {
        account_id: u32,
        mailbox_id: u32,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueNotify {
    pub task_types: TaskTypes,
    pub search_index: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskTypes(u32);

const _: () = assert!(TaskType::COUNT <= u32::BITS as usize);

impl TaskTypes {
    pub const ALL: TaskTypes = TaskTypes(u32::MAX >> (u32::BITS as usize - TaskType::COUNT));

    pub const fn from_bits(bits: u32) -> Self {
        TaskTypes(bits & Self::ALL.0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn insert(&mut self, typ: TaskType) {
        self.0 |= Self::bit(typ);
    }

    pub fn union(&mut self, other: TaskTypes) {
        self.0 |= other.0;
    }

    pub fn contains(self, typ: TaskType) -> bool {
        self.0 & Self::bit(typ) != 0
    }

    const fn bit(typ: TaskType) -> u32 {
        1 << typ as u32
    }
}

#[derive(Debug)]
pub struct BatchBuilder {
    current_account_id: Option<u32>,
    current_collection: Option<Collection>,
    current_document_id: Option<PendingId>,
    changes: VecMap<u32, ChangeLogBuilder>,
    changed_collections: VecMap<u32, ChangedCollection>,
    change_accounts: Vec<ChangeCounter>,
    reservations: Vec<Reservation>,
    bounds: Vec<CounterBound>,
    counters: counter::PendingCounters,
    next_slot: u32,
    batch_size: usize,
    batch_ops: usize,
    commit_points: Vec<CommitPointOffsets>,
    last_archive_hash: Option<u32>,
    last_index_partition: Option<(SearchIndex, u32)>,
    has_index_tasks: bool,
    task_types: TaskTypes,
    priority: CommitPriority,
    ops: Vec<Operation>,
}

#[derive(Debug, Default)]
pub struct ChangedCollection {
    pub changed_containers: Bitmap<SyncCollection>,
    pub changed_items: Bitmap<SyncCollection>,
    pub share_notification_id: Option<u64>,
}

#[derive(Debug)]
pub enum Operation {
    AccountId {
        account_id: u32,
    },
    Collection {
        collection: Collection,
    },
    DocumentId {
        document_id: PendingId,
    },
    AssertValue {
        class: ValueClass,
        assert_value: AssertValue,
    },
    Value {
        class: ValueClass,
        op: ValueOp,
    },
    Index {
        field: u8,
        key: Vec<u8>,
        set: bool,
    },
    Log {
        collection: LogCollection,
        set: LogSet,
    },
    ClearRange {
        subspace: Subspace,
        from: Vec<u8>,
        to: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum LogSet {
    Bytes(Vec<u8>),
    Pending(Box<log::Changes>),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum LogCollection {
    Sync(SyncCollection),
    Vanished(VanishedCollection),
    Private {
        collection: SyncCollection,
        viewer: u32,
    },
}

pub const PRIVATE_LOG: u8 = 0x80;

impl LogCollection {
    #[inline(always)]
    pub fn change_group(&self) -> ChangeGroup {
        match self {
            LogCollection::Sync(collection) | LogCollection::Private { collection, .. } => {
                collection.change_group()
            }
            LogCollection::Vanished(collection) => collection.change_group(),
        }
    }

    #[inline(always)]
    pub fn is_prefixed(&self) -> bool {
        match self {
            LogCollection::Sync(collection) | LogCollection::Private { collection, .. } => {
                collection.is_prefixed()
            }
            LogCollection::Vanished(_) => false,
        }
    }

    #[inline(always)]
    pub fn log_key(&self, account_id: u32, change_id: u64) -> ChangeLogKey {
        match *self {
            LogCollection::Private { collection, viewer } => ChangeLogKey::Private(PrivateLogKey {
                account_id,
                collection,
                viewer,
                change_id,
            }),
            collection => ChangeLogKey::Shared(LogKey {
                account_id,
                collection: u8::from(collection),
                change_id,
            }),
        }
    }
}

impl Batch<'_> {
    #[inline(always)]
    pub fn has_allocations(&self) -> bool {
        self.has_id_allocations() || !self.bounds.is_empty()
    }

    #[inline(always)]
    pub fn has_id_allocations(&self) -> bool {
        !self.change_accounts.is_empty() || !self.reservations.is_empty()
    }

    #[inline]
    pub fn allocations(&self) -> impl Iterator<Item = Allocation> + '_ {
        self.id_allocations()
            .chain(self.bounds.iter().map(|bound| Allocation::Bounded(*bound)))
    }

    #[inline]
    pub fn id_allocations(&self) -> impl Iterator<Item = Allocation> + '_ {
        self.change_accounts
            .iter()
            .map(|counter| Allocation::ChangeId(*counter))
            .chain(
                self.reservations
                    .iter()
                    .map(|reservation| Allocation::Reserved(*reservation)),
            )
    }

    #[inline(always)]
    pub fn bounds(&self) -> &[CounterBound] {
        self.bounds
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Allocation {
    ChangeId(ChangeCounter),
    Reserved(Reservation),
    Bounded(CounterBound),
}

#[derive(Debug)]
pub struct BatchCursor {
    account_id: u32,
    collection: u8,
    change_group: ChangeGroup,
    document_id: u32,
    has_changes: bool,
}

#[derive(Debug)]
pub enum Advance<'x> {
    Cursor,
    Value {
        class: &'x ValueClass,
        op: &'x mut ValueOp,
    },
    Index {
        field: u8,
        key: &'x [u8],
        set: bool,
    },
    Log {
        collection: LogCollection,
        set: &'x mut LogSet,
    },
    Assert {
        class: &'x ValueClass,
        assert_value: &'x AssertValue,
    },
    ClearRange {
        subspace: Subspace,
        from: &'x [u8],
        to: &'x [u8],
    },
}

impl BatchCursor {
    pub fn new(batch: &Batch<'_>) -> Self {
        BatchCursor {
            account_id: u32::MAX,
            collection: u8::MAX,
            change_group: SyncCollection::None.change_group(),
            document_id: u32::MAX,
            has_changes: !batch.change_accounts.is_empty(),
        }
    }

    #[inline(always)]
    pub fn advance<'x>(&mut self, op: &'x mut Operation, ids: &mut AssignedIds) -> Advance<'x> {
        match op {
            Operation::AccountId { account_id } => {
                self.account_id = *account_id;
                if self.has_changes {
                    ids.set_current_change_id(self.account_id, self.change_group);
                }
                Advance::Cursor
            }
            Operation::Collection { collection } => {
                self.collection = u8::from(*collection);
                self.change_group = collection.change_group();
                if self.has_changes {
                    ids.set_current_change_id(self.account_id, self.change_group);
                }
                Advance::Cursor
            }
            Operation::DocumentId { document_id } => {
                self.document_id = document_id.resolve(ids);
                Advance::Cursor
            }
            Operation::Value { class, op } => Advance::Value { class, op },
            Operation::Index { field, key, set } => Advance::Index {
                field: *field,
                key: key.as_slice(),
                set: *set,
            },
            Operation::Log { collection, set } => Advance::Log {
                collection: *collection,
                set,
            },
            Operation::AssertValue {
                class,
                assert_value,
            } => Advance::Assert {
                class,
                assert_value,
            },
            Operation::ClearRange { subspace, from, to } => Advance::ClearRange {
                subspace: *subspace,
                from,
                to,
            },
        }
    }

    #[inline(always)]
    pub fn account_id(&self) -> u32 {
        self.account_id
    }

    #[inline(always)]
    pub fn collection(&self) -> u8 {
        self.collection
    }

    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.document_id
    }

    #[inline(always)]
    pub fn subspace(&self, class: &ValueClass) -> Subspace {
        class.subspace(self.collection)
    }

    #[inline(always)]
    pub fn value_key(&self, class: &ValueClass, buf: &mut Vec<u8>, flags: u32) {
        buf.clear();
        class.serialize_into(
            buf,
            self.account_id,
            self.collection,
            self.document_id,
            flags,
        );
    }

    #[inline(always)]
    pub fn value_key_owned(&self, class: &ValueClass, flags: u32) -> Vec<u8> {
        class.serialize(self.account_id, self.collection, self.document_id, flags)
    }

    #[inline(always)]
    pub fn index_key(&self, field: u8, key: &[u8], buf: &mut Vec<u8>, flags: u32) {
        buf.clear();
        IndexKey {
            account_id: self.account_id,
            collection: self.collection,
            document_id: self.document_id,
            field,
            key,
        }
        .serialize_into(buf, flags);
    }

    #[inline(always)]
    pub fn index_key_owned(&self, field: u8, key: &[u8], flags: u32) -> Vec<u8> {
        IndexKey {
            account_id: self.account_id,
            collection: self.collection,
            document_id: self.document_id,
            field,
            key,
        }
        .serialize(flags)
    }

    #[inline(always)]
    pub fn log_key(
        &self,
        collection: LogCollection,
        ids: &AssignedIds,
        buf: &mut Vec<u8>,
        flags: u32,
    ) {
        let change_id = ids
            .change_id(self.account_id, collection.change_group())
            .unwrap_or_default();
        debug_assert!(
            change_id != 0,
            "no change id was allocated for this account"
        );
        buf.clear();
        collection
            .log_key(self.account_id, change_id)
            .serialize_into(buf, flags);
    }
}

impl Allocation {
    pub fn serialize_key_into(&self, buf: &mut Vec<u8>, flags: u32) {
        match self {
            Allocation::ChangeId(counter) => ValueClass::ChangeId(counter.group).serialize_into(
                buf,
                counter.account_id,
                0,
                0,
                flags,
            ),
            Allocation::Reserved(reservation) => reservation.serialize_key_into(buf, flags),
            Allocation::Bounded(bound) => bound.serialize_key_into(buf, flags),
        }
    }

    #[inline(always)]
    pub fn increment_by(&self) -> i64 {
        match self {
            Allocation::ChangeId(_) => 1,
            Allocation::Reserved(reservation) => reservation.count as i64,
            Allocation::Bounded(bound) => bound.by,
        }
    }
}

impl ReservationClass {
    #[inline(always)]
    pub fn sort_key(&self) -> (u8, u32, u32) {
        match *self {
            ReservationClass::DocumentId {
                account_id,
                collection,
            } => (0, account_id, u8::from(collection) as u32),
            ReservationClass::Uid {
                account_id,
                mailbox_id,
            } => (1, account_id, mailbox_id),
        }
    }
}

impl Reservation {
    pub fn serialize_key_into(&self, buf: &mut Vec<u8>, flags: u32) {
        match self.class {
            ReservationClass::DocumentId {
                account_id,
                collection,
            } => {
                ValueClass::DocumentId.serialize_into(buf, account_id, collection.into(), 0, flags)
            }
            ReservationClass::Uid {
                account_id,
                mailbox_id,
            } => ValueClass::MailboxUid.serialize_into(buf, account_id, 0, mailbox_id, flags),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum ValueClass {
    Property(u8),
    Immutable(u8),
    IndexProperty(IndexPropertyClass),
    MailboxUid,
    Acl(u32),
    TaskQueue(TaskQueueClass),
    Blob(BlobOp),
    Registry(RegistryClass),
    Queue(QueueClass),
    Telemetry(TelemetryClass),
    SearchIndex(SearchIndexClass),
    Any(AnyClass),
    ShareNotification {
        notification_id: u64,
        notify_account_id: u32,
    },
    DocumentId,
    ChangeId(ChangeGroup),
    Quota,
    ObjectCount(StorageQuota),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TenantQuota(u32),
    // SPDX-SnippetEnd
    NodeId(u16),
    Metadata(MetadataClass),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum IndexPropertyClass {
    Hash { property: u8, hash: Hash128 },
    Integer { property: u8, value: u64 },
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum SearchIndexClass {
    Term {
        index: SearchIndex,
        account_id: u32,
        field: u8,
        term: CheekyHash,
        block_id: u16,
    },
    Document {
        index: SearchIndex,
        account_id: u32,
        document_id: u32,
    },
    GlobalTerm {
        index: SearchIndex,
        field: u8,
        term: CheekyHash,
        block_id: u16,
    },
    GlobalDocument {
        index: SearchIndex,
        document_id: u64,
    },
    GlobalDocumentId {
        index: SearchIndex,
        block_id: u16,
    },
    Queue {
        index: SearchIndex,
        id_prefix: u32,
        id_suffix: QueueDocumentId,
        created_at: u64,
    },
    QueueIndex {
        index: SearchIndex,
        partition: u32,
    },
    QueueStatus {
        index: SearchIndex,
        partition: u32,
    },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum TaskQueueClass {
    Task { id: TaskId },
    Due { id: TaskId, typ: TaskType, due: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskDue {
    pub typ: TaskType,
    pub due: u64,
    pub id: u64,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TaskId {
    Assigned(u64),
    Document,
    DocumentTarget(u32),
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum QueueDocumentId {
    Assigned(u32),
    Current,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum SearchIndex {
    Email,
    Calendar,
    Contacts,
    File,
    Tracing,
    InMemory,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AnyClass {
    pub subspace: Subspace,
    pub key: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum RegistryClass {
    Item {
        object_id: u16,
        item_id: u64,
    },
    Reference {
        to_object_id: u16,
        to_item_id: u64,
        from_object_id: u16,
        from_item_id: u64,
    },
    Index {
        index_id: u16,
        object_id: u16,
        item_id: u64,
        key: Vec<u8>,
    },
    IndexId {
        object_id: u16,
        item_id: u64,
    },
    PrimaryKey {
        object_id: Option<u16>,
        index_id: u16,
        key: Vec<u8>,
    },
    IdCounter {
        object_id: u16,
    },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum QueueClass {
    Message(u64),
    MessageEvent(QueueEvent),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TenantMessage {
        tenant_id: u32,
        queue_id: u64,
    },
    // SPDX-SnippetEnd
    QuotaCount(Hash128),
    QuotaSize(Hash128),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum TelemetryClass {
    Span(u64),
    Metric(u64),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct QueueEvent {
    pub due: u64,
    pub queue_id: u64,
    pub queue_name: [u8; 8],
}

#[derive(Debug, Default)]
pub enum ValueOp {
    Set(SetValue),
    MergeFnc(MergeOperation),
    AtomicAdd(i64),
    AddAndGet(i64),
    #[default]
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Patch {
    pub offset: u32,
    pub source: PatchSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchSource {
    SlotBeU32(Slot),
    SlotArchivedU32 { slot: Slot, base: u32 },
    ChangeIdBe,
}

pub const MAX_CONCURRENT_ALLOCATIONS: usize = 16;

pub enum MergeResult {
    Update(Vec<u8>),
    Skip,
    Delete,
}

pub type MergeFnc =
    Box<dyn Fn(&AssignedIds, Option<&[u8]>) -> trc::Result<MergeResult> + Send + Sync>;

pub trait SerializeWithIds: Send + Sync {
    fn serialize_with_ids(&mut self, ids: &AssignedIds) -> trc::Result<(Vec<u8>, Option<u32>)>;

    fn size_hint(&self) -> usize;
}

#[repr(transparent)]
pub struct SerializeOperation(pub(crate) Box<dyn SerializeWithIds>);

#[derive(Debug)]
pub enum SetValue {
    Fixed(Vec<u8>),
    Patched(Vec<u8>, Box<[Patch]>),
    Serializable(SerializeOperation),
}

#[derive(Debug)]
pub struct SizedSetValue {
    pub value: SetValue,
    pub size_hint: usize,
}

impl SetValue {
    pub fn fixed(payload: Vec<u8>) -> SizedSetValue {
        SizedSetValue {
            size_hint: payload.len(),
            value: SetValue::Fixed(payload),
        }
    }

    pub fn patched(payload: Vec<u8>, patches: Vec<Patch>) -> SizedSetValue {
        debug_assert!(
            patches
                .iter()
                .all(|patch| (patch.offset as usize) < payload.len()),
            "patch offset is outside the payload"
        );

        SizedSetValue {
            size_hint: payload.len(),
            value: SetValue::Patched(payload, patches.into_boxed_slice()),
        }
    }

    pub fn serializable(object: impl SerializeWithIds + 'static) -> SizedSetValue {
        SizedSetValue {
            size_hint: object.size_hint(),
            value: SetValue::Serializable(SerializeOperation(Box::new(object))),
        }
    }

    pub fn resolve(&mut self, ids: &mut AssignedIds) -> trc::Result<Cow<'_, [u8]>> {
        match self {
            SetValue::Fixed(payload) => Ok(Cow::Borrowed(payload)),
            SetValue::Patched(payload, patches) => {
                Patch::apply(patches, payload, ids);
                Ok(Cow::Borrowed(payload))
            }
            SetValue::Serializable(object) => {
                let (payload, hash) = (object.0).serialize_with_ids(ids)?;
                ids.set_archive_hash(hash);
                Ok(Cow::Owned(payload))
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            SetValue::Fixed(payload) | SetValue::Patched(payload, _) => payload.len(),
            SetValue::Serializable(..) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Vec<u8>> for SizedSetValue {
    fn from(payload: Vec<u8>) -> Self {
        SetValue::fixed(payload)
    }
}

impl From<&[u8]> for SizedSetValue {
    fn from(payload: &[u8]) -> Self {
        SetValue::fixed(payload.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for SizedSetValue {
    fn from(payload: [u8; N]) -> Self {
        SetValue::fixed(payload.to_vec())
    }
}

impl From<&str> for SizedSetValue {
    fn from(payload: &str) -> Self {
        SetValue::fixed(payload.as_bytes().to_vec())
    }
}

impl From<String> for SizedSetValue {
    fn from(payload: String) -> Self {
        SetValue::fixed(payload.into_bytes())
    }
}

impl From<Cow<'_, [u8]>> for SizedSetValue {
    fn from(payload: Cow<'_, [u8]>) -> Self {
        SetValue::fixed(payload.into_owned())
    }
}

impl From<(Vec<u8>, Vec<Patch>)> for SizedSetValue {
    fn from((payload, patches): (Vec<u8>, Vec<Patch>)) -> Self {
        SetValue::patched(payload, patches)
    }
}

impl From<PendingId> for SizedSetValue {
    fn from(document_id: PendingId) -> Self {
        match document_id {
            PendingId::Assigned(document_id) => SetValue::fixed(document_id.to_be_bytes().to_vec()),
            PendingId::Slot(slot) => SetValue::patched(
                0u32.to_be_bytes().to_vec(),
                vec![Patch {
                    offset: 0,
                    source: PatchSource::SlotBeU32(slot),
                }],
            ),
        }
    }
}

impl From<Box<dyn SerializeWithIds>> for SizedSetValue {
    fn from(object: Box<dyn SerializeWithIds>) -> Self {
        SizedSetValue {
            size_hint: object.size_hint(),
            value: SetValue::Serializable(SerializeOperation(object)),
        }
    }
}

#[repr(transparent)]
pub struct MergeOperation(pub(crate) MergeFnc);

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum BlobOp {
    Commit { hash: BlobHash },
    Link { hash: BlobHash, to: BlobLink },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum BlobLink {
    Id { id: u64 },
    Document,
    Temporary { until: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AnyKey<T: AsRef<[u8]>> {
    pub subspace: Subspace,
    pub key: T,
}

pub trait TokenizeText {
    fn tokenize_into(&self, tokens: &mut HashSet<String>);
    fn to_tokens(&self) -> HashSet<String>;
}

impl TokenizeText for &str {
    fn tokenize_into(&self, tokens: &mut HashSet<String>) {
        for token in WordTokenizer::new(self, MAX_TOKEN_LENGTH) {
            tokens.insert(token.word.into_owned());
        }
    }

    fn to_tokens(&self) -> HashSet<String> {
        let mut tokens = HashSet::new();
        self.tokenize_into(&mut tokens);
        tokens
    }
}

pub trait IntoOperations {
    fn build(self, batch: &mut BatchBuilder) -> trc::Result<()>;
}

#[inline(always)]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl AsRef<ValueClass> for ValueClass {
    fn as_ref(&self) -> &ValueClass {
        self
    }
}

impl Slot {
    #[inline(always)]
    pub fn new(index: u32) -> Self {
        Slot(index)
    }

    #[inline(always)]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

impl SlotRange {
    #[inline(always)]
    pub fn new(first: Slot, count: u32) -> Self {
        SlotRange { first, count }
    }

    #[inline(always)]
    pub fn first(self) -> Slot {
        self.first
    }

    #[inline(always)]
    pub fn len(self) -> usize {
        self.count as usize
    }

    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.count == 0
    }

    #[inline(always)]
    pub fn iter(self) -> impl ExactSizeIterator<Item = Slot> {
        (self.first.0..self.first.0.saturating_add(self.count)).map(Slot)
    }
}

impl PendingId {
    #[inline(always)]
    pub fn resolve(self, ids: &AssignedIds) -> u32 {
        match self {
            PendingId::Assigned(document_id) => document_id,
            PendingId::Slot(slot) => ids.slot(slot),
        }
    }

    #[inline(always)]
    pub fn slot(self) -> Option<Slot> {
        match self {
            PendingId::Slot(slot) => Some(slot),
            PendingId::Assigned(_) => None,
        }
    }

    #[inline(always)]
    pub fn assigned(self) -> Option<u32> {
        match self {
            PendingId::Assigned(document_id) => Some(document_id),
            PendingId::Slot(_) => None,
        }
    }

    #[inline(always)]
    pub fn is_pending(self) -> bool {
        matches!(self, PendingId::Slot(_))
    }
}

impl From<u32> for PendingId {
    #[inline(always)]
    fn from(document_id: u32) -> Self {
        PendingId::Assigned(document_id)
    }
}

impl TaskId {
    #[inline(always)]
    pub fn resolve(self, account_id: u32, document_id: u32) -> u64 {
        match self {
            TaskId::Assigned(id) => id,
            TaskId::Document => {
                debug_assert!(account_id <= MAX_ACCOUNT_ID);
                Id::from_parts(account_id, document_id).id()
            }
            TaskId::DocumentTarget(target_id) => {
                TaskId::document_target(account_id, document_id, target_id)
            }
        }
    }

    pub fn document_target(account_id: u32, document_id: u32, target_id: u32) -> u64 {
        const GOLDEN_RATIO: u64 = 0x9E37_79B9_7F4A_7C15;
        const MIX_LOW: u64 = 0xBF58_476D_1CE4_E5B9;
        const MIX_HIGH: u64 = 0x94D0_49BB_1331_11EB;

        let mut hash = Id::from_parts(account_id, document_id).id().rotate_left(17)
            ^ (target_id as u64).wrapping_mul(GOLDEN_RATIO);
        hash ^= hash >> 30;
        hash = hash.wrapping_mul(MIX_LOW);
        hash ^= hash >> 27;
        hash = hash.wrapping_mul(MIX_HIGH);
        hash ^= hash >> 31;
        (hash & !DERIVED_ID_KIND) | TARGET_ID_MARKER
    }

    pub fn singleton_of(task: &Task) -> Option<u64> {
        task.singleton_key()
            .map(|(discriminant, key)| TaskId::singleton(task.object_type(), discriminant, key))
    }

    pub fn singleton(typ: TaskType, discriminant: u16, key: u64) -> u64 {
        let key =
            (u128::from(typ as u16) << 80) | (u128::from(discriminant) << 64) | u128::from(key);
        (xxh3_64(&key.to_be_bytes()) & !DERIVED_ID_KIND) | SINGLETON_ID_MARKER
    }

    pub fn shared_object(
        account_id: u32,
        collection: Collection,
        document_id: u32,
        window: u64,
    ) -> u64 {
        let key = (u128::from(Id::from_parts(account_id, document_id).id()) << 64)
            | (u128::from(u8::from(collection)) << 56)
            | u128::from(window & SHARED_OBJECT_WINDOW_MASK);
        (xxh3_64(&key.to_be_bytes()) & !DERIVED_ID_KIND) | SHARED_OBJECT_ID_MARKER
    }
}

pub const MAX_ACCOUNT_ID: u32 = (1 << 30) - 1;
const DERIVED_ID_KIND: u64 = 0b11 << 62;
const SINGLETON_ID_MARKER: u64 = 0b01 << 62;
const TARGET_ID_MARKER: u64 = 0b10 << 62;
const SHARED_OBJECT_ID_MARKER: u64 = 0b11 << 62;
const SHARED_OBJECT_WINDOW_MASK: u64 = (1 << 56) - 1;

impl QueueDocumentId {
    #[inline(always)]
    pub fn resolve(self, document_id: u32) -> u32 {
        match self {
            QueueDocumentId::Assigned(document_id) => document_id,
            QueueDocumentId::Current => document_id,
        }
    }
}

impl From<u32> for QueueDocumentId {
    #[inline(always)]
    fn from(document_id: u32) -> Self {
        QueueDocumentId::Assigned(document_id)
    }
}

impl From<u64> for TaskId {
    #[inline(always)]
    fn from(id: u64) -> Self {
        TaskId::Assigned(id)
    }
}

impl From<Slot> for PendingId {
    #[inline(always)]
    fn from(slot: Slot) -> Self {
        PendingId::Slot(slot)
    }
}

impl AssignedIds {
    #[inline(always)]
    pub fn mark(&self) -> AssignedIdsMark {
        AssignedIdsMark {
            slots: self.slots.len(),
            change_ids: self.change_ids.len(),
            counter: self.counter,
            archive_hash: self.archive_hash,
        }
    }

    #[inline(always)]
    pub fn rollback(&mut self, mark: AssignedIdsMark) {
        self.slots.truncate(mark.slots);
        self.change_ids.truncate(mark.change_ids);
        self.counter = mark.counter;
        self.archive_hash = mark.archive_hash;
        self.current_change_id = 0;
    }

    pub fn push_archive_hash(&mut self, hash: u32) {
        self.archive_hash = Some(hash);
    }

    pub fn set_archive_hash(&mut self, hash: Option<u32>) {
        if hash.is_some() {
            self.archive_hash = hash;
        }
    }

    #[inline(always)]
    pub fn last_archive_hash(&self) -> Option<u32> {
        self.archive_hash
    }

    pub fn push_counter_id(&mut self, id: i64) {
        self.counter = Some(id);
    }

    pub fn push_change_id(&mut self, counter: ChangeCounter, change_id: u64) {
        self.change_ids.push(ChangeId { counter, change_id });
    }

    #[inline]
    pub fn apply(&mut self, allocation: Allocation, last_id: i64) -> trc::Result<()> {
        match allocation {
            Allocation::ChangeId(counter) => self.push_change_id(counter, last_id as u64),
            Allocation::Reserved(reservation) => {
                self.fill_slots(reservation.first_slot, reservation.count, last_id as u32)
            }
            Allocation::Bounded(bound) => bound.verify(last_id)?,
        }
        Ok(())
    }

    pub fn fill_slots(&mut self, first_slot: Slot, count: u32, last_id: u32) {
        debug_assert!(last_id >= count, "{last_id} < {count}");
        debug_assert_ne!(last_id, u32::MAX, "document id space is exhausted");

        let first = first_slot.index();
        if self.slots.len() < first + count as usize {
            self.slots.resize(first + count as usize, u32::MAX);
        }
        let base = last_id - count + 1;
        for offset in 0..count {
            self.slots[first + offset as usize] = base + offset;
        }
    }

    #[inline(always)]
    pub fn slot(&self, slot: Slot) -> u32 {
        let document_id = self.slots[slot.index()];
        debug_assert_ne!(document_id, u32::MAX, "slot {slot:?} was never assigned");
        document_id
    }

    #[inline(always)]
    pub fn slots(&self, range: SlotRange) -> impl Iterator<Item = u32> + '_ {
        let first = range.first().index();
        self.slots[first..first + range.len()]
            .iter()
            .inspect(|id| {
                debug_assert_ne!(**id, u32::MAX, "a slot in the range was never assigned");
            })
            .copied()
    }

    pub fn change_counters(&self) -> impl Iterator<Item = ChangeCounter> + '_ {
        self.change_ids.iter().map(|id| id.counter)
    }

    pub fn change_ids(
        &self,
        account_id: u32,
        group: impl Into<ChangeGroup>,
    ) -> impl Iterator<Item = u64> + '_ {
        let counter = ChangeCounter {
            account_id,
            group: group.into(),
        };
        self.change_ids
            .iter()
            .filter(move |id| id.counter == counter)
            .map(|id| id.change_id)
    }

    pub fn change_id(&self, account_id: u32, group: impl Into<ChangeGroup>) -> Option<u64> {
        let counter = ChangeCounter {
            account_id,
            group: group.into(),
        };
        self.change_ids
            .iter()
            .filter(|id| id.counter == counter)
            .map(|id| id.change_id)
            .next_back()
    }

    pub fn last_change_id(&self, account_id: u32, group: impl Into<ChangeGroup>) -> u64 {
        let group = group.into();
        let change_id = self.change_id(account_id, group);
        debug_assert!(
            change_id.is_some(),
            "no change id was created for account {account_id} group {group:?}"
        );
        change_id.unwrap_or_default()
    }

    #[inline(always)]
    pub fn current_change_id(&self) -> u64 {
        debug_assert_ne!(self.current_change_id, 0, "no current change id is set");
        self.current_change_id
    }

    #[inline(always)]
    pub fn try_current_change_id(&self) -> Option<u64> {
        Some(self.current_change_id).filter(|change_id| *change_id != 0)
    }

    #[inline(always)]
    pub(crate) fn set_current_change_id(&mut self, account_id: u32, group: ChangeGroup) -> u64 {
        self.current_change_id = self.change_id(account_id, group).unwrap_or_default();
        self.current_change_id
    }

    #[inline(always)]
    pub fn last_counter_id(&self) -> i64 {
        debug_assert!(self.counter.is_some(), "no counter id was created");
        self.counter.unwrap_or_default()
    }
}

impl Patch {
    pub fn apply(patches: &[Patch], payload: &mut [u8], ids: &AssignedIds) {
        for patch in patches {
            let offset = patch.offset as usize;
            match patch.source {
                PatchSource::SlotBeU32(slot) => {
                    payload[offset..offset + U32_LEN]
                        .copy_from_slice(&ids.slot(slot).to_be_bytes());
                }
                PatchSource::SlotArchivedU32 { slot, base } => {
                    payload[offset..offset + U32_LEN]
                        .copy_from_slice(&(ids.slot(slot) + base).to_le_bytes());
                    Archive::<ArchiveBytes>::restamp_hash(payload);
                }
                PatchSource::ChangeIdBe => {
                    payload[offset..offset + U64_LEN]
                        .copy_from_slice(&ids.current_change_id().to_be_bytes());
                }
            }
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Archive<T> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ArchiveVersion {
    pub fn hash(&self) -> Option<u32> {
        match self {
            ArchiveVersion::Versioned { hash, .. } => Some(*hash),
            ArchiveVersion::Hashed { hash } => Some(*hash),
            ArchiveVersion::Unversioned => None,
        }
    }

    pub fn change_id(&self) -> Option<u64> {
        match self {
            ArchiveVersion::Versioned { change_id, .. } => Some(*change_id),
            _ => None,
        }
    }
}

impl From<LogCollection> for u8 {
    fn from(value: LogCollection) -> Self {
        match value {
            LogCollection::Sync(col) => col as u8,
            LogCollection::Vanished(col) => col as u8,
            LogCollection::Private { collection, .. } => PRIVATE_LOG | collection as u8,
        }
    }
}

impl From<ContactField> for ValueClass {
    fn from(value: ContactField) -> Self {
        ValueClass::Property(value.into())
    }
}

impl From<CalendarEventField> for ValueClass {
    fn from(value: CalendarEventField) -> Self {
        ValueClass::Property(value.into())
    }
}

impl From<CalendarNotificationField> for ValueClass {
    fn from(value: CalendarNotificationField) -> Self {
        ValueClass::Property(value.into())
    }
}

impl From<EmailField> for ValueClass {
    fn from(value: EmailField) -> Self {
        match value {
            EmailField::Metadata | EmailField::SortKeys => ValueClass::Immutable(value.into()),
            _ => ValueClass::Property(value.into()),
        }
    }
}

impl From<MailboxField> for ValueClass {
    fn from(value: MailboxField) -> Self {
        match value {
            MailboxField::UidCounter => ValueClass::MailboxUid,
            _ => ValueClass::Property(value.into()),
        }
    }
}

impl From<PrincipalField> for ValueClass {
    fn from(value: PrincipalField) -> Self {
        ValueClass::Property(value.into())
    }
}

impl From<SieveField> for ValueClass {
    fn from(value: SieveField) -> Self {
        ValueClass::Property(value.into())
    }
}

impl From<EmailSubmissionField> for ValueClass {
    fn from(value: EmailSubmissionField) -> Self {
        ValueClass::Property(value.into())
    }
}

impl From<Field> for ValueClass {
    fn from(value: Field) -> Self {
        ValueClass::Property(value.into())
    }
}

pub struct PendingTask {
    pub task: Task,
    pub slot: Slot,
}

impl SerializeWithIds for PendingTask {
    fn serialize_with_ids(&mut self, ids: &AssignedIds) -> trc::Result<(Vec<u8>, Option<u32>)> {
        self.task.set_document_id(Id::from(ids.slot(self.slot)));

        Ok((self.task.to_pickled_vec(), None))
    }

    fn size_hint(&self) -> usize {
        self.task.size_hint()
    }
}

impl std::fmt::Debug for SerializeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SerializeOperation")
    }
}

impl std::fmt::Debug for MergeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MergeOperation")
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/write/tests.rs"]
mod tests;
