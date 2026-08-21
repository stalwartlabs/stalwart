/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::assert::AssertValue;
use crate::{Subspace, backend::MAX_TOKEN_LENGTH};
use log::ChangeLogBuilder;
use nlp::tokenizers::word::WordTokenizer;
use std::{
    collections::HashSet,
    hash::Hash,
    time::{Duration, SystemTime},
};
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection, VanishedCollection},
    field::{
        CalendarEventField, CalendarNotificationField, ContactField, EmailField,
        EmailSubmissionField, Field, MailboxField, PrincipalField, SieveField,
    },
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

#[derive(Debug, Default)]
pub struct AssignedIds {
    pub ids: Vec<AssignedId>,
    current_change_id: Option<u64>,
}

#[derive(Debug)]
pub enum AssignedId {
    Counter(i64),
    ChangeId(ChangeId),
}

#[derive(Debug, Clone, Copy)]
pub struct ChangeId {
    pub account_id: u32,
    pub change_id: u64,
}

#[cfg(not(feature = "test_mode"))]
pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 10;
#[cfg(not(feature = "test_mode"))]
pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(10);

#[cfg(feature = "test_mode")]
pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 1000;
#[cfg(feature = "test_mode")]
pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(3600);

#[derive(Debug)]
pub struct Batch<'x> {
    pub(crate) change_accounts: &'x [u32],
    pub(crate) ops: &'x mut [Operation],
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
    current_document_id: Option<u32>,
    changes: VecMap<u32, ChangeLogBuilder>,
    changed_collections: VecMap<u32, ChangedCollection>,
    change_accounts: Vec<u32>,
    has_assertions: bool,
    batch_size: usize,
    batch_ops: usize,
    commit_points: Vec<usize>,
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
        document_id: u32,
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
        set: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum LogCollection {
    Sync(SyncCollection),
    Vanished(VanishedCollection),
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
    ChangeId,
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
        id_suffix: u32,
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
    Task { id: u64 },
    Due { id: u64, due: u64 },
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
    QuotaCount(Vec<u8>),
    QuotaSize(Vec<u8>),
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
    Set(Vec<u8>),
    SetFnc {
        payload: Vec<u8>,
        fnc: SetOperation,
    },
    MergeFnc(MergeOperation),
    AtomicAdd(i64),
    AddAndGet(i64),
    #[default]
    Clear,
}

pub enum MergeResult {
    Update(Vec<u8>),
    Skip,
    Delete,
}

pub type SetFnc = Box<dyn Fn(&AssignedIds, &mut [u8]) -> trc::Result<()> + Send + Sync>;
pub type MergeFnc =
    Box<dyn Fn(&AssignedIds, Option<&[u8]>) -> trc::Result<MergeResult> + Send + Sync>;

#[repr(transparent)]
pub struct MergeOperation(pub(crate) MergeFnc);

#[repr(transparent)]
pub struct SetOperation(pub(crate) SetFnc);

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

impl AssignedIds {
    pub fn push_counter_id(&mut self, id: i64) {
        self.ids.push(AssignedId::Counter(id));
    }

    pub fn push_change_id(&mut self, account_id: u32, change_id: u64) {
        self.ids.push(AssignedId::ChangeId(ChangeId {
            account_id,
            change_id,
        }));
    }

    pub fn change_id(&self, account_id: u32) -> Option<u64> {
        self.ids
            .iter()
            .filter_map(|id| match id {
                AssignedId::ChangeId(change_id) if change_id.account_id == account_id => {
                    Some(change_id.change_id)
                }
                _ => None,
            })
            .next_back()
    }

    pub fn last_change_id(&self, account_id: u32) -> trc::Result<u64> {
        self.change_id(account_id).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No change ids were created")
        })
    }

    pub fn current_change_id(&self) -> trc::Result<u64> {
        self.current_change_id.ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No current change id is set")
        })
    }

    pub(crate) fn set_current_change_id(&mut self, account_id: u32) -> u64 {
        self.current_change_id = self.change_id(account_id);
        self.current_change_id.unwrap_or_default()
    }

    pub fn last_counter_id(&self) -> trc::Result<i64> {
        self.ids
            .iter()
            .filter_map(|id| match id {
                AssignedId::Counter(counter_id) => Some(*counter_id),
                _ => None,
            })
            .next_back()
            .ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Reason, "No counter ids were created")
            })
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

impl SetOperation {
    fn id(&self) -> usize {
        &*self.0 as *const _ as *const u8 as usize
    }
}

impl std::fmt::Debug for MergeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MergeOperation").field(&self.id()).finish()
    }
}

impl std::fmt::Debug for SetOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SetOperation").field(&self.id()).finish()
    }
}

impl PartialEq for MergeOperation {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for MergeOperation {}

impl PartialEq for SetOperation {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for SetOperation {}

impl Hash for MergeOperation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl Hash for SetOperation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}
