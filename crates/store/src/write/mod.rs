/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::assert::AssertValue;
use crate::{Subspace, U32_LEN, U64_LEN, backend::MAX_TOKEN_LENGTH};
use log::ChangeLogBuilder;
use nlp::tokenizers::word::WordTokenizer;
use registry::{schema::structs::Task, types::ObjectImpl};
use std::{borrow::Cow, collections::HashSet, hash::Hash, time::SystemTime};
use tinyvec::TinyVec;
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection, VanishedCollection},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Slot(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingId {
    Assigned(u32),
    Slot(Slot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeGroup {
    pub account_id: u32,
    pub group: u8,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ChangeId {
    pub account_id: u32,
    pub group: u8,
    pub change_id: u64,
}

#[derive(Debug, Default)]
pub struct AssignedIds {
    slots: TinyVec<[u32; 8]>,
    change_ids: TinyVec<[ChangeId; 2]>,
    counters: TinyVec<[i64; 1]>,
    archive_hashes: TinyVec<[u32; 1]>,
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
    counters: usize,
    archive_hashes: usize,
}

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation"
))]
pub(crate) use commit_limits::{MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME};

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation"
))]
pub(crate) use commit_limits::commit_backoff;

#[cfg(any(
    feature = "rocks",
    feature = "postgres",
    feature = "mysql",
    feature = "foundation"
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
    const MAX_COMMIT_BACKOFF_US: u64 = 50_000;
    const MAX_COMMIT_BACKOFF_SHIFT: u32 = 8;

    pub(crate) fn commit_backoff(attempt: u32) -> Duration {
        let ceiling = (MIN_COMMIT_BACKOFF_US << attempt.min(MAX_COMMIT_BACKOFF_SHIFT))
            .min(MAX_COMMIT_BACKOFF_US);

        Duration::from_micros(rand::rng().random_range(0..=ceiling))
    }
}

#[derive(Debug)]
pub struct Batch<'x> {
    pub(crate) change_accounts: &'x [ChangeGroup],
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
    change_accounts: Vec<ChangeGroup>,
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

#[derive(Debug, PartialEq, Eq, Hash)]
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

#[derive(Debug, PartialEq, Eq, Hash)]
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
    pub fn change_group(&self) -> u8 {
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
        buf.clear();
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
    ChangeId(u8),
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
        id_suffix: PendingId,
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

#[derive(Debug, PartialEq, Eq, Hash, Default)]
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
}

#[repr(transparent)]
pub struct SerializeOperation(pub(crate) Box<dyn SerializeWithIds>);

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum SetValue {
    Fixed(Vec<u8>),
    Patched(Vec<u8>, Box<[Patch]>),
    Serializable(SerializeOperation),
}

impl SetValue {
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

impl PendingId {
    #[inline(always)]
    pub fn resolve(self, ids: &AssignedIds) -> u32 {
        match self {
            PendingId::Assigned(document_id) => document_id,
            PendingId::Slot(slot) => ids.slot(slot),
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
            counters: self.counters.len(),
            archive_hashes: self.archive_hashes.len(),
        }
    }

    #[inline(always)]
    pub fn rollback(&mut self, mark: AssignedIdsMark) {
        self.slots.truncate(mark.slots);
        self.change_ids.truncate(mark.change_ids);
        self.counters.truncate(mark.counters);
        self.archive_hashes.truncate(mark.archive_hashes);
        self.current_change_id = 0;
    }

    pub fn push_archive_hash(&mut self, hash: u32) {
        self.archive_hashes.push(hash);
    }

    pub fn set_archive_hash(&mut self, hash: Option<u32>) {
        if let Some(hash) = hash {
            self.archive_hashes.push(hash);
        }
    }

    #[inline(always)]
    pub fn last_archive_hash(&self) -> Option<u32> {
        self.archive_hashes.last().copied()
    }

    pub fn push_counter_id(&mut self, id: i64) {
        self.counters.push(id);
    }

    pub fn push_change_id(&mut self, account_id: u32, group: u8, change_id: u64) {
        self.change_ids.push(ChangeId {
            account_id,
            group,
            change_id,
        });
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

    pub fn change_id(&self, account_id: u32, group: u8) -> Option<u64> {
        self.change_ids
            .iter()
            .filter(|id| id.account_id == account_id && id.group == group)
            .map(|id| id.change_id)
            .next_back()
    }

    pub fn last_change_id(&self, account_id: u32, group: u8) -> u64 {
        let change_id = self.change_id(account_id, group);
        debug_assert!(
            change_id.is_some(),
            "no change id was created for account {account_id} group {group}"
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
    pub(crate) fn set_current_change_id(&mut self, account_id: u32, group: u8) -> u64 {
        self.current_change_id = self.change_id(account_id, group).unwrap_or_default();
        self.current_change_id
    }

    pub fn last_counter_id(&self) -> trc::Result<i64> {
        self.counters.last().copied().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No counter ids were created")
        })
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

impl MergeOperation {
    fn id(&self) -> usize {
        &*self.0 as *const _ as *const u8 as usize
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
}

impl SerializeOperation {
    fn id(&self) -> usize {
        &*self.0 as *const _ as *const u8 as usize
    }
}

impl std::fmt::Debug for SerializeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SerializeOperation")
            .field(&self.id())
            .finish()
    }
}

impl PartialEq for SerializeOperation {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for SerializeOperation {}

impl Hash for SerializeOperation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl std::fmt::Debug for MergeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MergeOperation").field(&self.id()).finish()
    }
}

impl PartialEq for MergeOperation {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for MergeOperation {}

impl Hash for MergeOperation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}
