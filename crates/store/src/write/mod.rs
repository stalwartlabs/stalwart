/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::assert::AssertValue;
use crate::{IndexKey, Key, LogKey, Subspace, U32_LEN, U64_LEN, backend::MAX_TOKEN_LENGTH};
use log::ChangeLogBuilder;
use nlp::tokenizers::word::WordTokenizer;
use registry::{schema::structs::Task, types::ObjectImpl};
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
    map::{bitmap::Bitmap, vec_map::VecMap},
};

pub mod assert;
pub mod batch;
pub mod bitpack;
pub mod blob;
pub mod compress;
pub mod key;
pub mod lazybitmap;
pub mod log;
pub mod serialize;

pub use compress::{ArchiveCompression, Compression, Dictionary};

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

pub const DOCUMENT_ID_SET: u32 = 0;

const _: () = assert!(std::mem::size_of::<rkyv::primitive::FixedUsize>() == 4);
const _: () = assert!(std::mem::align_of::<rkyv::primitive::ArchivedU64>() == 1);
const _: () = assert!(std::mem::align_of::<rkyv::string::ArchivedString>() == 1);

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
    feature = "foundation",
    feature = "sqlite"
))]
pub(crate) use commit_limits::ChunkedRetry;

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation",
    feature = "sqlite"
))]
mod commit_limits {
    use rand::RngExt;
    use std::time::Duration;

    #[cfg(not(feature = "test_mode"))]
    pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 24;
    #[cfg(not(feature = "test_mode"))]
    pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(10);

    #[cfg(feature = "test_mode")]
    pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 1000;
    #[cfg(feature = "test_mode")]
    pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(3600);

    const MIN_COMMIT_BACKOFF_US: u64 = 250;
    const MAX_COMMIT_BACKOFF_US: u64 = 1_000_000;
    const MAX_COMMIT_BACKOFF_SHIFT: u32 = 12;

    pub(crate) fn commit_backoff(attempt: u32) -> Duration {
        let ceiling = (MIN_COMMIT_BACKOFF_US << attempt.min(MAX_COMMIT_BACKOFF_SHIFT))
            .min(MAX_COMMIT_BACKOFF_US);

        Duration::from_micros(rand::rng().random_range(0..=ceiling))
    }

    pub(crate) struct ChunkedRetry {
        chunk_size: Option<usize>,
        first_chunk_size: usize,
        min_chunk_size: usize,
        retry_count: u32,
    }

    impl ChunkedRetry {
        pub(crate) fn unbounded(first_chunk_size: usize, min_chunk_size: usize) -> Self {
            Self {
                chunk_size: None,
                first_chunk_size,
                min_chunk_size,
                retry_count: 0,
            }
        }

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

        pub(crate) fn is_chunk_full(&self, fetched: usize) -> bool {
            self.chunk_size.is_some_and(|chunk_size| fetched >= chunk_size)
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
                Some(_) if self.retry_count < MAX_COMMIT_ATTEMPTS => {
                    tokio::time::sleep(commit_backoff(self.retry_count)).await;
                    self.retry_count += 1;
                    true
                }
                Some(_) => false,
            }
        }
    }
}

#[derive(Debug)]
pub struct Batch<'x> {
    pub(crate) change_accounts: &'x [ChangeCounter],
    pub(crate) reservations: &'x [Reservation],
    pub(crate) ops: &'x mut [Operation],
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
    pub tasks: bool,
    pub search_index: bool,
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
    next_slot: u32,
    has_assertions: bool,
    batch_size: usize,
    batch_ops: usize,
    commit_points: Vec<CommitPointOffsets>,
    last_archive_hash: Option<u32>,
    last_index_partition: Option<(SearchIndex, u32)>,
    has_index_tasks: bool,
    has_tasks: bool,
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
}

impl LogCollection {
    #[inline(always)]
    pub fn change_group(&self) -> ChangeGroup {
        match self {
            LogCollection::Sync(collection) => collection.change_group(),
            LogCollection::Vanished(collection) => collection.change_group(),
        }
    }

    #[inline(always)]
    pub fn is_prefixed(&self) -> bool {
        match self {
            LogCollection::Sync(collection) => collection.is_prefixed(),
            LogCollection::Vanished(_) => false,
        }
    }
}

impl Batch<'_> {
    #[inline(always)]
    pub fn has_allocations(&self) -> bool {
        !self.change_accounts.is_empty() || !self.reservations.is_empty()
    }

    #[inline]
    pub fn allocations(&self) -> impl Iterator<Item = Allocation> + '_ {
        self.change_accounts
            .iter()
            .map(|counter| Allocation::ChangeId(*counter))
            .chain(
                self.reservations
                    .iter()
                    .map(|reservation| Allocation::Reserved(*reservation)),
            )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Allocation {
    ChangeId(ChangeCounter),
    Reserved(Reservation),
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
        LogKey {
            account_id: self.account_id,
            collection: u8::from(collection),
            change_id,
        }
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
        }
    }

    #[inline(always)]
    pub fn increment_by(&self) -> i64 {
        match self {
            Allocation::ChangeId(_) => 1,
            Allocation::Reserved(reservation) => reservation.count as i64,
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
    InMemory(InMemoryClass),
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
    TenantQuota(u32),
    NodeId(u16),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum IndexPropertyClass {
    Hash { property: u8, hash: u128 },
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
    Due { id: TaskId, due: u64 },
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TaskId {
    Assigned(u64),
    Document,
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
pub enum InMemoryClass {
    Key(Vec<u8>),
    Counter(Vec<u8>),
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
    QuotaCount(u128),
    QuotaSize(u128),
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

    #[inline(always)]
    pub fn offset(self, offset: usize) -> Slot {
        Slot(
            self.0
                .checked_add(u32::try_from(offset).expect("slot offset is out of range"))
                .expect("slot offset is out of range"),
        )
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
    pub fn last(self) -> Slot {
        debug_assert_ne!(self.count, 0, "an empty slot range has no last slot");
        self.first.offset(self.count.saturating_sub(1) as usize)
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
    pub fn get(self, offset: usize) -> Slot {
        debug_assert!(offset < self.len(), "slot offset is outside the range");
        self.first.offset(offset)
    }

    #[inline(always)]
    pub fn iter(self) -> impl Iterator<Item = Slot> {
        (0..self.count).map(move |offset| Slot(self.first.0 + offset))
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
            TaskId::Document => Id::from_parts(account_id, document_id).id(),
        }
    }
}

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
    pub fn apply(&mut self, allocation: Allocation, last_id: i64) {
        match allocation {
            Allocation::ChangeId(counter) => self.push_change_id(counter, last_id as u64),
            Allocation::Reserved(reservation) => {
                self.fill_slots(reservation.first_slot, reservation.count, last_id as u32)
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn document_ids(account_id: u32) -> ReservationClass {
        ReservationClass::DocumentId {
            account_id,
            collection: Collection::Email,
        }
    }

    fn group(group: u8) -> ChangeGroup {
        ChangeGroup::from_u8(group)
    }

    fn counter(account_id: u32, group_: u8) -> ChangeCounter {
        ChangeCounter {
            account_id,
            group: group(group_),
        }
    }

    #[test]
    fn slot_index_and_offset() {
        assert_eq!(Slot::new(0).index(), 0);
        assert_eq!(Slot::new(7).index(), 7);
        assert_eq!(Slot::new(7).offset(0), Slot::new(7));
        assert_eq!(Slot::new(7).offset(3), Slot::new(10));
        assert!(Slot::new(3) < Slot::new(4));
    }

    #[test]
    fn slot_offset_rejects_overflow() {
        assert!(std::panic::catch_unwind(|| Slot::new(u32::MAX).offset(1)).is_err());
        assert!(
            std::panic::catch_unwind(|| Slot::new(0).offset(u32::MAX as usize + 1)).is_err(),
            "an offset that does not fit in a u32 must not wrap"
        );
    }

    #[test]
    fn fill_slots_numbers_the_range_ending_at_the_counter() {
        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 4, 4);

        assert_eq!(
            (0..4).map(|n| ids.slot(Slot::new(n))).collect::<Vec<_>>(),
            vec![1, 2, 3, 4],
            "a counter that advanced to 4 by 4 must yield 1..=4"
        );

        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 1, 1000);
        assert_eq!(ids.slot(Slot::new(0)), 1000);

        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 3, 3);
        assert_eq!(ids.slot(Slot::new(0)), 1, "ids must start at 1, not 0");
    }

    #[test]
    fn fill_slots_accepts_reservations_out_of_slot_order() {
        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(4), 2, 12);
        ids.fill_slots(Slot::new(0), 4, 4);
        ids.fill_slots(Slot::new(6), 1, 77);

        assert_eq!(
            (0..7).map(|n| ids.slot(Slot::new(n))).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 11, 12, 77],
            "sorting reservations by class must not disturb slot numbering"
        );
    }

    #[test]
    fn pending_id_resolves_through_assigned_ids() {
        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 2, 9);

        assert_eq!(PendingId::Assigned(3).resolve(&ids), 3);
        assert_eq!(PendingId::Slot(Slot::new(1)).resolve(&ids), 9);
        assert_eq!(PendingId::Assigned(3).assigned(), Some(3));
        assert_eq!(PendingId::Slot(Slot::new(1)).assigned(), None);
        assert!(!PendingId::Assigned(3).is_pending());
        assert!(PendingId::Slot(Slot::new(0)).is_pending());
        assert_eq!(PendingId::from(5u32), PendingId::Assigned(5));
    }

    #[test]
    fn rollback_undoes_an_aborted_attempt() {
        let mut ids = AssignedIds::default();
        let mark = ids.mark();

        ids.fill_slots(Slot::new(0), 3, 3);
        ids.push_change_id(counter(1, 0), 100);
        ids.push_counter_id(42);
        ids.push_archive_hash(0xdead);
        ids.set_current_change_id(1, group(0));

        ids.rollback(mark);

        assert_eq!(
            ids.change_id(1, group(0)),
            None,
            "an aborted attempt left a change id behind"
        );
        assert_eq!(ids.try_current_change_id(), None);
        assert!(ids.last_archive_hash().is_none());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ids.last_counter_id()))
                .is_err(),
            "an aborted attempt left a counter id behind"
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ids.slot(Slot::new(0))))
                .is_err(),
            "an aborted attempt left a document id behind"
        );

        ids.fill_slots(Slot::new(0), 3, 6);
        ids.push_change_id(counter(1, 0), 101);
        assert_eq!(
            (0..3).map(|n| ids.slot(Slot::new(n))).collect::<Vec<_>>(),
            vec![4, 5, 6],
            "the retry must observe only its own ids"
        );
        assert_eq!(ids.change_id(1, group(0)), Some(101));
    }

    #[test]
    fn rollback_preserves_an_earlier_commit_point() {
        let mut ids = AssignedIds::default();

        ids.fill_slots(Slot::new(0), 2, 2);
        ids.push_change_id(counter(1, 0), 100);
        ids.push_counter_id(7);
        ids.push_archive_hash(0xaaaa);

        let mark = ids.mark();

        ids.fill_slots(Slot::new(2), 2, 4);
        ids.push_change_id(counter(1, 0), 101);
        ids.push_counter_id(8);
        ids.push_archive_hash(0xbbbb);

        ids.rollback(mark);

        assert_eq!(
            (0..2).map(|n| ids.slot(Slot::new(n))).collect::<Vec<_>>(),
            vec![1, 2],
            "rollback truncated ids belonging to an earlier commit point"
        );
        assert_eq!(ids.change_id(1, group(0)), Some(100));
        assert_eq!(ids.last_counter_id(), 7);
        assert_eq!(ids.last_archive_hash(), Some(0xaaaa));

        ids.fill_slots(Slot::new(2), 2, 9);
        assert_eq!(
            (0..4).map(|n| ids.slot(Slot::new(n))).collect::<Vec<_>>(),
            vec![1, 2, 8, 9]
        );
    }

    #[test]
    fn change_ids_are_tracked_per_group() {
        let mut ids = AssignedIds::default();
        ids.push_change_id(counter(1, 0), 10);
        ids.push_change_id(counter(1, 3), 20);
        ids.push_change_id(counter(2, 0), 30);

        assert_eq!(ids.change_id(1, group(0)), Some(10));
        assert_eq!(ids.change_id(1, group(3)), Some(20));
        assert_eq!(ids.change_id(2, group(0)), Some(30));
        assert_eq!(ids.change_id(2, group(3)), None);
        assert_eq!(ids.change_id(3, group(0)), None);

        assert_eq!(ids.set_current_change_id(1, group(3)), 20);
        assert_eq!(ids.current_change_id(), 20);
        assert_eq!(ids.set_current_change_id(1, group(0)), 10);
        assert_eq!(ids.current_change_id(), 10);
        assert_eq!(
            ids.set_current_change_id(9, group(9)),
            0,
            "an unknown group must not inherit another group's change id"
        );
        assert_eq!(ids.try_current_change_id(), None);
    }

    #[test]
    fn change_id_returns_the_latest_for_a_group() {
        let mut ids = AssignedIds::default();
        ids.push_change_id(counter(1, 0), 10);
        ids.push_change_id(counter(1, 0), 11);
        ids.push_change_id(counter(1, 0), 12);

        assert_eq!(
            ids.change_id(1, group(0)),
            Some(12),
            "a batch spanning commit points must stamp the latest change id"
        );
    }

    #[test]
    fn patches_are_applied_at_their_offsets() {
        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 2, 0x0203);
        ids.push_change_id(counter(1, 0), 0x0102_0304_0506_0708);
        ids.set_current_change_id(1, group(0));

        let mut payload = vec![0xffu8; 16];
        Patch::apply(
            &[
                Patch {
                    offset: 0,
                    source: PatchSource::ChangeIdBe,
                },
                Patch {
                    offset: 8,
                    source: PatchSource::SlotBeU32(Slot::new(1)),
                },
                Patch {
                    offset: 12,
                    source: PatchSource::SlotBeU32(Slot::new(0)),
                },
            ],
            &mut payload,
            &ids,
        );

        assert_eq!(&payload[0..8], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&payload[8..12], &0x0000_0203u32.to_be_bytes());
        assert_eq!(&payload[12..16], &0x0000_0202u32.to_be_bytes());
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, PartialEq, Eq)]
    struct PatchTarget {
        name: String,
        id: u32,
        trailing: Vec<u32>,
    }

    impl ArchiveCompression for PatchTarget {
        const COMPRESSION: Compression = Compression::Zstd(Some(Dictionary::Common));
    }

    fn patch_target(id: u32) -> PatchTarget {
        PatchTarget {
            name: "a mailbox name long enough to clear the dictionary watermark".to_string(),
            id,
            trailing: (0..16).collect(),
        }
    }

    #[test]
    fn an_archived_slot_patch_rewrites_the_field_and_the_hash() {
        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 1, 41);
        ids.push_change_id(counter(1, 0), 7);
        ids.set_current_change_id(1, group(0));

        for versioned in [false, true] {
            let archiver = Archiver::new(patch_target(0));
            let (payload_len, mut archive) = if versioned {
                archiver.with_version().serialize_patchable()
            } else {
                archiver.serialize_patchable()
            }
            .expect("serialize");

            let offset = payload_len as usize - std::mem::size_of::<ArchivedPatchTarget>()
                + std::mem::offset_of!(ArchivedPatchTarget, id);
            let mut patches = vec![Patch {
                offset: offset as u32,
                source: PatchSource::SlotArchivedU32 {
                    slot: Slot::new(0),
                    base: 1,
                },
            }];
            if versioned {
                patches.push(Patch {
                    offset: (archive.len() - U64_LEN - 1) as u32,
                    source: PatchSource::ChangeIdBe,
                });
            }

            Patch::apply(&patches, &mut archive, &ids);

            let stored = <Archive<ArchiveBytes> as crate::Deserialize>::deserialize(&archive)
                .expect("the patched archive failed its integrity check");
            assert_eq!(
                stored.version.change_id(),
                versioned.then_some(7),
                "change id was not stamped"
            );
            assert_eq!(
                stored.deserialize::<PatchTarget>().expect("unarchive"),
                patch_target(42),
                "the patched field did not round trip"
            );
        }
    }

    #[test]
    fn patching_the_same_archive_twice_is_idempotent() {
        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 1, 41);

        let (payload_len, mut archive) = Archiver::new(patch_target(0))
            .serialize_patchable()
            .expect("serialize");
        let patches = [Patch {
            offset: (payload_len as usize - std::mem::size_of::<ArchivedPatchTarget>()
                + std::mem::offset_of!(ArchivedPatchTarget, id)) as u32,
            source: PatchSource::SlotArchivedU32 {
                slot: Slot::new(0),
                base: 1,
            },
        }];

        Patch::apply(&patches, &mut archive, &ids);
        let once = archive.clone();
        Patch::apply(&patches, &mut archive, &ids);

        assert_eq!(once, archive, "a retried patch changed the payload");
    }

    #[test]
    fn a_patchable_archive_is_never_compressed() {
        let (payload_len, archive) = Archiver::new(patch_target(0))
            .serialize_patchable()
            .expect("serialize");
        let compressed =
            crate::Serialize::serialize(&Archiver::new(patch_target(0))).expect("serialize");

        assert!(
            compressed.len() < archive.len(),
            "the sample must be large enough to compress, otherwise this proves nothing"
        );
        assert_eq!(
            payload_len as usize,
            archive.len() - U32_LEN - 1,
            "an unversioned patchable archive carries a hash and a marker"
        );
    }

    #[test]
    fn reservation_keys_distinguish_classes() {
        let mut document_key = Vec::new();
        Reservation {
            class: document_ids(1),
            first_slot: Slot::new(0),
            count: 1,
        }
        .serialize_key_into(&mut document_key, 0);

        let mut other_collection = Vec::new();
        Reservation {
            class: ReservationClass::DocumentId {
                account_id: 1,
                collection: Collection::Mailbox,
            },
            first_slot: Slot::new(0),
            count: 1,
        }
        .serialize_key_into(&mut other_collection, 0);

        let mut uid_key = Vec::new();
        Reservation {
            class: ReservationClass::Uid {
                account_id: 1,
                mailbox_id: 0,
            },
            first_slot: Slot::new(0),
            count: 1,
        }
        .serialize_key_into(&mut uid_key, 0);

        assert_ne!(document_key, other_collection);
        assert_ne!(document_key, uid_key);
        assert_ne!(other_collection, uid_key);
    }

    #[test]
    fn reservation_sort_key_orders_by_class_then_target() {
        assert!(document_ids(1).sort_key() < document_ids(2).sort_key());
        assert!(
            document_ids(u32::MAX).sort_key()
                < ReservationClass::Uid {
                    account_id: 0,
                    mailbox_id: 0,
                }
                .sort_key(),
            "document id reservations must sort before uid reservations"
        );
        assert!(
            ReservationClass::Uid {
                account_id: 1,
                mailbox_id: 1,
            }
            .sort_key()
                < ReservationClass::Uid {
                    account_id: 1,
                    mailbox_id: 2,
                }
                .sort_key()
        );
    }
}
