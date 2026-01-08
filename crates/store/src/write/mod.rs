/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::assert::AssertValue;
use crate::backend::MAX_TOKEN_LENGTH;
use log::ChangeLogBuilder;
use nlp::tokenizers::word::WordTokenizer;
use rkyv::util::AlignedVec;
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
pub mod key;
pub mod log;
pub mod serialize;

pub(crate) const ARCHIVE_ALIGNMENT: usize = 16;

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

#[derive(Debug, Clone)]
pub enum AlignedBytes {
    Aligned(AlignedVec<ARCHIVE_ALIGNMENT>),
    Vec(Vec<u8>),
}

pub struct Archiver<T>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    pub inner: T,
    pub flags: u8,
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
    pub(crate) changes: &'x VecMap<u32, ChangedCollection>,
    pub(crate) ops: &'x mut [Operation],
}

#[derive(Debug)]
pub struct BatchBuilder {
    current_account_id: Option<u32>,
    current_collection: Option<Collection>,
    current_document_id: Option<u32>,
    changes: VecMap<u32, ChangeLogBuilder>,
    changed_collections: VecMap<u32, ChangedCollection>,
    has_assertions: bool,
    batch_size: usize,
    batch_ops: usize,
    commit_points: Vec<usize>,
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
    IndexProperty(IndexPropertyClass),
    Acl(u32),
    InMemory(InMemoryClass),
    TaskQueue(TaskQueueClass),
    Directory(DirectoryClass),
    Blob(BlobOp),
    Config(Vec<u8>),
    Queue(QueueClass),
    Report(ReportClass),
    Telemetry(TelemetryClass),
    SearchIndex(SearchIndexClass),
    Any(AnyClass),
    ShareNotification {
        notification_id: u64,
        notify_account_id: u32,
    },
    DocumentId,
    ChangeId,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum IndexPropertyClass {
    Hash { property: u8, hash: CheekyHash },
    Integer { property: u8, value: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct SearchIndexClass {
    pub index: SearchIndex,
    pub id: SearchIndexId,
    pub typ: SearchIndexType,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum SearchIndexType {
    Term { field: u8, hash: CheekyHash },
    Index { field: SearchIndexField },
    Document,
}

pub(crate) const SEARCH_INDEX_MAX_FIELD_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq, Clone, Hash, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub struct SearchIndexField {
    pub(crate) field_id: u8,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum SearchIndexId {
    Account { account_id: u32, document_id: u32 },
    Global { id: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum TaskQueueClass {
    UpdateIndex {
        due: TaskEpoch,
        index: SearchIndex,
        is_insert: bool,
    },
    SendAlarm {
        due: TaskEpoch,
        event_id: u16,
        alarm_id: u16,
        is_email_alert: bool,
    },
    SendImip {
        due: TaskEpoch,
        is_payload: bool,
    },
    MergeThreads {
        due: TaskEpoch,
    },
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
#[repr(transparent)]
pub struct TaskEpoch(pub(crate) u64);

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
    pub subspace: u8,
    pub key: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum InMemoryClass {
    Key(Vec<u8>),
    Counter(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum DirectoryClass {
    NameToId(Vec<u8>),
    EmailToId(Vec<u8>),
    Index { word: Vec<u8>, principal_id: u32 },
    MemberOf { principal_id: u32, member_of: u32 },
    Members { principal_id: u32, has_member: u32 },
    Principal(u32),
    UsedQuota(u32),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum QueueClass {
    Message(u64),
    MessageEvent(QueueEvent),
    DmarcReportHeader(ReportEvent),
    DmarcReportEvent(ReportEvent),
    TlsReportHeader(ReportEvent),
    TlsReportEvent(ReportEvent),
    QuotaCount(Vec<u8>),
    QuotaSize(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum ReportClass {
    Tls { id: u64, expires: u64 },
    Dmarc { id: u64, expires: u64 },
    Arf { id: u64, expires: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum TelemetryClass {
    Span {
        span_id: u64,
    },
    Metric {
        timestamp: u64,
        metric_id: u64,
        node_id: u64,
    },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct QueueEvent {
    pub due: u64,
    pub queue_id: u64,
    pub queue_name: [u8; 8],
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct ReportEvent {
    pub due: u64,
    pub policy_hash: u64,
    pub seq_id: u64,
    pub domain: String,
}

#[derive(Debug, PartialEq, Eq, Hash, Default)]
pub enum ValueOp {
    Set(Vec<u8>),
    SetFnc(SetOperation),
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Param {
    I64(i64),
    U64(u64),
    String(String),
    Bytes(Vec<u8>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Params(Vec<Param>);

pub type SetFnc = fn(&Params, &AssignedIds) -> trc::Result<Vec<u8>>;
pub type MergeFnc = fn(&Params, &AssignedIds, Option<&[u8]>) -> trc::Result<MergeResult>;

#[derive(Debug, Clone)]
pub struct MergeOperation {
    pub(crate) fnc: MergeFnc,
    pub(crate) params: Params,
}

#[derive(Debug, Clone)]
pub struct SetOperation {
    pub(crate) fnc: SetFnc,
    pub(crate) params: Params,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum BlobOp {
    Commit { hash: BlobHash },
    Link { hash: BlobHash, to: BlobLink },
    Quota { hash: BlobHash, until: u64 },
    Undelete { hash: BlobHash, until: u64 },
    SpamSample { hash: BlobHash, until: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum BlobLink {
    Id { id: u64 },
    Document,
    Temporary { until: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AnyKey<T: AsRef<[u8]>> {
    pub subspace: u8,
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

    pub fn last_change_id(&self, account_id: u32) -> trc::Result<u64> {
        self.ids
            .iter()
            .filter_map(|id| match id {
                AssignedId::ChangeId(change_id) if change_id.account_id == account_id => {
                    Some(change_id.change_id)
                }
                _ => None,
            })
            .next_back()
            .ok_or_else(|| {
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

    pub(crate) fn set_current_change_id(&mut self, account_id: u32) -> trc::Result<u64> {
        let change_id = self.last_change_id(account_id)?;
        self.current_change_id = Some(change_id);
        Ok(change_id)
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

impl QueueClass {
    pub fn due(&self) -> Option<u64> {
        match self {
            QueueClass::DmarcReportHeader(report_event) => report_event.due.into(),
            QueueClass::TlsReportHeader(report_event) => report_event.due.into(),
            _ => None,
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
        ValueClass::Property(value.into())
    }
}

impl From<MailboxField> for ValueClass {
    fn from(value: MailboxField) -> Self {
        ValueClass::Property(value.into())
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

impl PartialEq for MergeOperation {
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params
    }
}

impl Eq for MergeOperation {}

impl PartialEq for SetOperation {
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params
    }
}

impl Eq for SetOperation {}

impl Hash for MergeOperation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.params.hash(state);
    }
}

impl Hash for SetOperation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.params.hash(state);
    }
}

impl SetOperation {
    pub fn params(&self) -> &Params {
        &self.params
    }
}

impl MergeOperation {
    pub fn params(&self) -> &Params {
        &self.params
    }
}

impl Params {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_i64(mut self, value: i64) -> Self {
        self.0.push(Param::I64(value));
        self
    }

    pub fn with_u64(mut self, value: u64) -> Self {
        self.0.push(Param::U64(value));
        self
    }

    pub fn with_string(mut self, value: String) -> Self {
        self.0.push(Param::String(value));
        self
    }

    pub fn with_str(mut self, value: &str) -> Self {
        self.0.push(Param::String(value.to_string()));
        self
    }

    pub fn with_bytes(mut self, value: Vec<u8>) -> Self {
        self.0.push(Param::Bytes(value));
        self
    }

    pub fn with_bool(mut self, value: bool) -> Self {
        self.0.push(Param::Bool(value));
        self
    }

    pub fn i64(&self, idx: usize) -> i64 {
        match &self.0[idx] {
            Param::I64(v) => *v,
            _ => panic!("Param at index {} is not an i64", idx),
        }
    }

    pub fn u64(&self, idx: usize) -> u64 {
        match &self.0[idx] {
            Param::U64(v) => *v,
            _ => panic!("Param at index {} is not a u64", idx),
        }
    }

    pub fn string(&self, idx: usize) -> &str {
        match &self.0[idx] {
            Param::String(v) => v.as_str(),
            _ => panic!("Param at index {} is not a String", idx),
        }
    }

    pub fn bytes(&self, idx: usize) -> &[u8] {
        match &self.0[idx] {
            Param::Bytes(v) => v.as_slice(),
            _ => panic!("Param at index {} is not Bytes", idx),
        }
    }

    pub fn bool(&self, idx: usize) -> bool {
        match &self.0[idx] {
            Param::Bool(v) => *v,
            _ => panic!("Param at index {} is not a bool", idx),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[Param] {
        &self.0
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[Param]> for Params {
    fn as_ref(&self) -> &[Param] {
        &self.0
    }
}

impl TaskEpoch {
    /*
      Structure of the 64-bit epoch:
       4 bytes: seconds since custom epoch (1632280000)
       2 bytes: attempt number
       2 bytes: sequence id
    */

    const EPOCH_OFFSET: u64 = 1632280000;

    pub fn now() -> Self {
        Self::new(now())
    }

    pub fn new(timestamp: u64) -> Self {
        Self(timestamp.saturating_sub(Self::EPOCH_OFFSET) << 32)
    }

    pub fn with_attempt(mut self, attempt: u16) -> Self {
        self.0 |= (attempt as u64) << 16;
        self
    }

    pub fn with_sequence_id(mut self, sequence_id: u16) -> Self {
        self.0 |= sequence_id as u64;
        self
    }

    pub fn with_random_sequence_id(self) -> Self {
        self.with_sequence_id(rand::random())
    }

    pub fn due(&self) -> u64 {
        (self.0 >> 32) + Self::EPOCH_OFFSET
    }

    pub fn attempt(&self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub fn sequence_id(&self) -> u16 {
        self.0 as u16
    }

    pub fn inner(&self) -> u64 {
        self.0
    }

    pub fn from_inner(inner: u64) -> Self {
        Self(inner)
    }
}
