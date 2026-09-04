/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

pub mod backend;
pub mod build;
pub mod dispatch;
pub mod query;
pub mod registry;
pub mod search;
pub mod write;

use ::registry::schema::enums::CompressionAlgo;
pub use ahash;
pub use blake3;
pub use parking_lot;
pub use rand;
pub use rkyv;
pub use roaring;
use utils::snowflake::SnowflakeIdGenerator;
pub use xxhash_rust;

use crate::backend::{elastic::ElasticSearchStore, meili::MeiliSearchStore};
use ahash::AHashMap;
use backend::{ephemeral::EphemeralStore, fs::FsStore, http::HttpStore, memory::StaticMemoryStore};
use std::{borrow::Cow, path::PathBuf, sync::Arc};
use write::ValueClass;

pub trait Deserialize: Sized + Sync + Send {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self>;

    #[inline(always)]
    fn deserialize_owned(bytes: Vec<u8>) -> trc::Result<Self> {
        Self::deserialize(&bytes)
    }

    #[inline(always)]
    fn deserialize_with_key(_: &[u8], bytes: &[u8]) -> trc::Result<Self> {
        Self::deserialize(bytes)
    }

    #[inline(always)]
    fn deserialize_owned_with_key(key: &[u8], bytes: Vec<u8>) -> trc::Result<Self> {
        Self::deserialize_with_key(key, &bytes)
    }
}

pub trait Serialize {
    fn serialize(&self) -> trc::Result<Vec<u8>>;
}

pub trait SerializeInfallible {
    fn serialize(&self) -> Vec<u8>;
}

// Key serialization flags
pub(crate) const WITH_SUBSPACE: u32 = 1;

pub trait Key: Sync + Send + Clone {
    fn serialize_into(&self, buf: &mut Vec<u8>, flags: u32);
    fn key_len_hint(&self) -> usize;
    fn subspace(&self) -> Subspace;

    #[inline]
    fn serialize(&self, flags: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.key_len_hint() + 1);
        self.serialize_into(&mut buf, flags);
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IndexKey<T: AsRef<[u8]>> {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub field: u8,
    pub key: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexKeyPrefix {
    pub account_id: u32,
    pub collection: u8,
    pub field: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueKey<T: AsRef<ValueClass>> {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub class: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogKey {
    pub account_id: u32,
    pub collection: u8,
    pub change_id: u64,
}

pub const U128_LEN: usize = std::mem::size_of::<u128>();
pub const U64_LEN: usize = std::mem::size_of::<u64>();
pub const U32_LEN: usize = std::mem::size_of::<u32>();
pub const U16_LEN: usize = std::mem::size_of::<u16>();

const _: () = {
    let mut index = 0;
    while index < Subspace::ALL.len() {
        assert!(Subspace::ALL[index].index() == index);
        index += 1;
    }
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Subspace {
    Acl = b'a',
    RegistryIndex = b'b',
    Immutable = b'c',
    Directory = b'd',
    QueueMessage = b'e',
    TaskQueue = b'f',
    RegistryPrimaryKey = b'g',
    ReportOut = b'h',
    Indexes = b'i',
    DeletedItems = b'j',
    BlobLink = b'k',
    Logs = b'l',
    InMemoryValue = b'm',
    Counter = b'n',
    TelemetrySpan = b'o',
    Property = b'p',
    QueueEvent = b'q',
    ReportIn = b'r',
    Registry = b's',
    Blobs = b't',
    Quota = b'u',
    IndexProperty = b'v',
    SpamSamples = b'w',
    TelemetryMetric = b'x',
    InMemoryCounter = b'y',
    SearchTerm = b'z',
    GlobalCounter = b'C',
    SearchDocument = b'D',
    SearchQueue = b'Q',
    System = b'Y',
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shape {
    Value,
    Presence,
    Counter,
}

impl Subspace {
    pub const ALL: &'static [Subspace] = &[
        Subspace::Acl,
        Subspace::RegistryIndex,
        Subspace::Immutable,
        Subspace::Directory,
        Subspace::QueueMessage,
        Subspace::TaskQueue,
        Subspace::RegistryPrimaryKey,
        Subspace::ReportOut,
        Subspace::Indexes,
        Subspace::DeletedItems,
        Subspace::BlobLink,
        Subspace::Logs,
        Subspace::InMemoryValue,
        Subspace::Counter,
        Subspace::TelemetrySpan,
        Subspace::Property,
        Subspace::QueueEvent,
        Subspace::ReportIn,
        Subspace::Registry,
        Subspace::Blobs,
        Subspace::Quota,
        Subspace::IndexProperty,
        Subspace::SpamSamples,
        Subspace::TelemetryMetric,
        Subspace::InMemoryCounter,
        Subspace::SearchTerm,
        Subspace::GlobalCounter,
        Subspace::SearchDocument,
        Subspace::SearchQueue,
        Subspace::System,
    ];

    #[inline(always)]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    #[inline(always)]
    pub const fn index(self) -> usize {
        match self {
            Subspace::Acl => 0,
            Subspace::RegistryIndex => 1,
            Subspace::Immutable => 2,
            Subspace::Directory => 3,
            Subspace::QueueMessage => 4,
            Subspace::TaskQueue => 5,
            Subspace::RegistryPrimaryKey => 6,
            Subspace::ReportOut => 7,
            Subspace::Indexes => 8,
            Subspace::DeletedItems => 9,
            Subspace::BlobLink => 10,
            Subspace::Logs => 11,
            Subspace::InMemoryValue => 12,
            Subspace::Counter => 13,
            Subspace::TelemetrySpan => 14,
            Subspace::Property => 15,
            Subspace::QueueEvent => 16,
            Subspace::ReportIn => 17,
            Subspace::Registry => 18,
            Subspace::Blobs => 19,
            Subspace::Quota => 20,
            Subspace::IndexProperty => 21,
            Subspace::SpamSamples => 22,
            Subspace::TelemetryMetric => 23,
            Subspace::InMemoryCounter => 24,
            Subspace::SearchTerm => 25,
            Subspace::GlobalCounter => 26,
            Subspace::SearchDocument => 27,
            Subspace::SearchQueue => 28,
            Subspace::System => 29,
        }
    }

    pub const fn try_from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            b'a' => Subspace::Acl,
            b'b' => Subspace::RegistryIndex,
            b'c' => Subspace::Immutable,
            b'd' => Subspace::Directory,
            b'e' => Subspace::QueueMessage,
            b'f' => Subspace::TaskQueue,
            b'g' => Subspace::RegistryPrimaryKey,
            b'h' => Subspace::ReportOut,
            b'i' => Subspace::Indexes,
            b'j' => Subspace::DeletedItems,
            b'k' => Subspace::BlobLink,
            b'l' => Subspace::Logs,
            b'm' => Subspace::InMemoryValue,
            b'n' => Subspace::Counter,
            b'o' => Subspace::TelemetrySpan,
            b'p' => Subspace::Property,
            b'q' => Subspace::QueueEvent,
            b'r' => Subspace::ReportIn,
            b's' => Subspace::Registry,
            b't' => Subspace::Blobs,
            b'u' => Subspace::Quota,
            b'v' => Subspace::IndexProperty,
            b'w' => Subspace::SpamSamples,
            b'x' => Subspace::TelemetryMetric,
            b'y' => Subspace::InMemoryCounter,
            b'z' => Subspace::SearchTerm,
            b'C' => Subspace::GlobalCounter,
            b'D' => Subspace::SearchDocument,
            b'Q' => Subspace::SearchQueue,
            b'Y' => Subspace::System,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Subspace::Acl => "a",
            Subspace::RegistryIndex => "b",
            Subspace::Immutable => "c",
            Subspace::Directory => "d",
            Subspace::QueueMessage => "e",
            Subspace::TaskQueue => "f",
            Subspace::RegistryPrimaryKey => "g",
            Subspace::ReportOut => "h",
            Subspace::Indexes => "i",
            Subspace::DeletedItems => "j",
            Subspace::BlobLink => "k",
            Subspace::Logs => "l",
            Subspace::InMemoryValue => "m",
            Subspace::Counter => "n",
            Subspace::TelemetrySpan => "o",
            Subspace::Property => "p",
            Subspace::QueueEvent => "q",
            Subspace::ReportIn => "r",
            Subspace::Registry => "s",
            Subspace::Blobs => "t",
            Subspace::Quota => "u",
            Subspace::IndexProperty => "v",
            Subspace::SpamSamples => "w",
            Subspace::TelemetryMetric => "x",
            Subspace::InMemoryCounter => "y",
            Subspace::SearchTerm => "z",
            Subspace::GlobalCounter => "gc",
            Subspace::SearchDocument => "sd",
            Subspace::SearchQueue => "sq",
            Subspace::System => "sy",
        }
    }

    pub const fn shape(self) -> Shape {
        match self {
            Subspace::Indexes | Subspace::RegistryIndex => Shape::Presence,
            Subspace::Counter
            | Subspace::Quota
            | Subspace::InMemoryCounter
            | Subspace::GlobalCounter => Shape::Counter,
            Subspace::Acl
            | Subspace::Immutable
            | Subspace::Directory
            | Subspace::QueueMessage
            | Subspace::TaskQueue
            | Subspace::RegistryPrimaryKey
            | Subspace::ReportOut
            | Subspace::DeletedItems
            | Subspace::BlobLink
            | Subspace::Logs
            | Subspace::InMemoryValue
            | Subspace::TelemetrySpan
            | Subspace::Property
            | Subspace::QueueEvent
            | Subspace::ReportIn
            | Subspace::Registry
            | Subspace::Blobs
            | Subspace::IndexProperty
            | Subspace::SpamSamples
            | Subspace::TelemetryMetric
            | Subspace::SearchTerm
            | Subspace::SearchDocument
            | Subspace::SearchQueue
            | Subspace::System => Shape::Value,
        }
    }

    pub const fn is_internal_fts(self) -> bool {
        matches!(self, Subspace::SearchTerm | Subspace::SearchDocument)
    }
}

impl From<Subspace> for u8 {
    #[inline(always)]
    fn from(subspace: Subspace) -> Self {
        subspace as u8
    }
}

#[derive(Clone)]
pub struct IterateParams<T: Key> {
    begin: T,
    end: T,
    first: bool,
    ascending: bool,
    values: bool,
    expected_rows: Option<usize>,
}

#[derive(Clone, Default)]
pub struct LookupStores {
    pub stores: AHashMap<Box<str>, InMemoryStore>,
}

#[derive(Clone, Default)]
pub enum Store {
    #[cfg(feature = "sqlite")]
    SQLite(Arc<backend::sqlite::SqliteStore>),
    #[cfg(feature = "foundation")]
    FoundationDb(Arc<backend::foundationdb::FdbStore>),
    #[cfg(feature = "postgres")]
    PostgreSQL(Arc<backend::postgres::PostgresStore>),
    #[cfg(feature = "mysql")]
    MySQL(Arc<backend::mysql::MysqlStore>),
    #[cfg(feature = "rocks")]
    RocksDb(Arc<backend::rocksdb::RocksDbStore>),
    Ephemeral(Arc<EphemeralStore>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
    SQLReadReplica(Arc<backend::composite::read_replica::SQLReadReplica>),
    // SPDX-SnippetEnd
    #[default]
    None,
}

#[derive(Clone)]
pub enum BlobStore {
    Store(Store),
    Fs(Arc<FsStore>),
    #[cfg(feature = "s3")]
    S3(Arc<backend::s3::S3Store>),
    #[cfg(feature = "azure")]
    Azure(Arc<backend::azure::AzureStore>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded(Arc<backend::composite::sharded_blob::ShardedBlob>),
    // SPDX-SnippetEnd
}

#[derive(Clone)]
pub enum SearchStore {
    Store(Store),
    #[cfg(feature = "postgres")]
    PostgreSQL(Arc<backend::postgres::PostgresStore>),
    #[cfg(feature = "mysql")]
    MySQL(Arc<backend::mysql::MysqlStore>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
    SQLReadReplica(Arc<backend::composite::read_replica::SQLReadReplica>),
    // SPDX-SnippetEnd
    ElasticSearch(Arc<ElasticSearchStore>),
    MeiliSearch(Arc<MeiliSearchStore>),
}

#[derive(Clone, Debug)]
pub enum InMemoryStore {
    Store(Store),
    #[cfg(feature = "redis")]
    Redis(Arc<backend::redis::RedisStore>),
    Http(Arc<HttpStore>),
    Static(Arc<StaticMemoryStore>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded(Arc<backend::composite::sharded_lookup::ShardedInMemory>),
    // SPDX-SnippetEnd
}

#[derive(Clone)]
pub struct RegistryStore(pub(crate) Arc<RegistryStoreInner>);

#[derive(Clone)]
pub struct RegistryStoreInner {
    pub(crate) local_path: PathBuf,
    pub(crate) store: Store,
    pub(crate) node_id: u16,
    pub(crate) env_recovery_mode: bool,
    pub(crate) env_recovery_admin: Option<(String, String)>,
    pub(crate) env_cluster_role: Option<String>,
    pub(crate) env_push_shard_id: u32,
    pub(crate) env_hostname: String,
    pub(crate) env_public_url: Option<String>,
    pub(crate) id_generator: SnowflakeIdGenerator,
}

#[cfg(feature = "sqlite")]
impl From<backend::sqlite::SqliteStore> for Store {
    fn from(store: backend::sqlite::SqliteStore) -> Self {
        Self::SQLite(Arc::new(store))
    }
}

#[cfg(feature = "foundation")]
impl From<backend::foundationdb::FdbStore> for Store {
    fn from(store: backend::foundationdb::FdbStore) -> Self {
        Self::FoundationDb(Arc::new(store))
    }
}

#[cfg(feature = "postgres")]
impl From<backend::postgres::PostgresStore> for Store {
    fn from(store: backend::postgres::PostgresStore) -> Self {
        Self::PostgreSQL(Arc::new(store))
    }
}

#[cfg(feature = "mysql")]
impl From<backend::mysql::MysqlStore> for Store {
    fn from(store: backend::mysql::MysqlStore) -> Self {
        Self::MySQL(Arc::new(store))
    }
}

#[cfg(feature = "rocks")]
impl From<backend::rocksdb::RocksDbStore> for Store {
    fn from(store: backend::rocksdb::RocksDbStore) -> Self {
        Self::RocksDb(Arc::new(store))
    }
}

impl From<EphemeralStore> for Store {
    fn from(store: EphemeralStore) -> Self {
        Self::Ephemeral(Arc::new(store))
    }
}

impl From<ElasticSearchStore> for SearchStore {
    fn from(store: ElasticSearchStore) -> Self {
        Self::ElasticSearch(Arc::new(store))
    }
}

impl From<MeiliSearchStore> for SearchStore {
    fn from(store: MeiliSearchStore) -> Self {
        Self::MeiliSearch(Arc::new(store))
    }
}

#[cfg(feature = "redis")]
impl From<backend::redis::RedisStore> for InMemoryStore {
    fn from(store: backend::redis::RedisStore) -> Self {
        Self::Redis(Arc::new(store))
    }
}

impl From<Store> for SearchStore {
    fn from(store: Store) -> Self {
        Self::Store(store)
    }
}

impl From<Store> for InMemoryStore {
    fn from(store: Store) -> Self {
        Self::Store(store)
    }
}

impl From<Store> for BlobStore {
    fn from(store: Store) -> Self {
        Self::Store(store)
    }
}

impl Default for BlobStore {
    fn default() -> Self {
        Self::Store(Store::None)
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::Store(Store::None)
    }
}

impl Default for SearchStore {
    fn default() -> Self {
        Self::Store(Store::None)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value<'x> {
    Integer(i64),
    Bool(bool),
    Float(f64),
    Text(Cow<'x, str>),
    Blob(Cow<'x, [u8]>),
    Null,
}

impl Eq for Value<'_> {}

impl<'x> Value<'x> {
    pub fn to_str<'y: 'x>(&'y self) -> Cow<'x, str> {
        match self {
            Value::Text(s) => s.as_ref().into(),
            Value::Integer(i) => Cow::Owned(i.to_string()),
            Value::Bool(b) => Cow::Owned(b.to_string()),
            Value::Float(f) => Cow::Owned(f.to_string()),
            Value::Blob(b) => String::from_utf8_lossy(b.as_ref()),
            Value::Null => Cow::Borrowed(""),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    pub values: Vec<Value<'static>>,
}

#[derive(Clone, Debug)]
pub struct Rows {
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug)]
pub struct NamedRows {
    pub names: Vec<String>,
    pub rows: Vec<Row>,
}

#[derive(Clone, Copy)]
pub enum QueryType {
    Execute,
    Exists,
    QueryAll,
    QueryOne,
}

pub trait QueryResult: Sync + Send + 'static {
    fn from_exec(items: usize) -> Self;
    fn from_exists(exists: bool) -> Self;
    fn from_query_one(items: impl IntoRows) -> Self;
    fn from_query_all(items: impl IntoRows) -> Self;

    fn query_type() -> QueryType;
}

pub trait IntoRows {
    fn into_row(self) -> Option<Row>;
    fn into_rows(self) -> Rows;
    fn into_named_rows(self) -> NamedRows;
}

impl QueryResult for Option<Row> {
    fn query_type() -> QueryType {
        QueryType::QueryOne
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(_: impl IntoRows) -> Self {
        unreachable!()
    }

    fn from_query_one(items: impl IntoRows) -> Self {
        items.into_row()
    }
}

impl QueryResult for Rows {
    fn query_type() -> QueryType {
        QueryType::QueryAll
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(items: impl IntoRows) -> Self {
        items.into_rows()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl QueryResult for NamedRows {
    fn query_type() -> QueryType {
        QueryType::QueryAll
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(items: impl IntoRows) -> Self {
        items.into_named_rows()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl QueryResult for bool {
    fn query_type() -> QueryType {
        QueryType::Exists
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(exists: bool) -> Self {
        exists
    }

    fn from_query_all(_: impl IntoRows) -> Self {
        unreachable!()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl QueryResult for usize {
    fn query_type() -> QueryType {
        QueryType::Execute
    }

    fn from_exec(items: usize) -> Self {
        items
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(_: impl IntoRows) -> Self {
        unreachable!()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl<'x> From<&'x str> for Value<'x> {
    fn from(value: &'x str) -> Self {
        Self::Text(value.into())
    }
}

impl From<String> for Value<'_> {
    fn from(value: String) -> Self {
        Self::Text(value.into())
    }
}

impl<'x> From<&'x String> for Value<'x> {
    fn from(value: &'x String) -> Self {
        Self::Text(value.into())
    }
}

impl<'x> From<Cow<'x, str>> for Value<'x> {
    fn from(value: Cow<'x, str>) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for Value<'_> {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for Value<'_> {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<Value<'static>> for i64 {
    fn from(value: Value<'static>) -> Self {
        if let Value::Integer(value) = value {
            value
        } else {
            0
        }
    }
}

impl From<u64> for Value<'_> {
    fn from(value: u64) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u32> for Value<'_> {
    fn from(value: u32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<f64> for Value<'_> {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl<'x> From<&'x [u8]> for Value<'x> {
    fn from(value: &'x [u8]) -> Self {
        Self::Blob(value.into())
    }
}

impl From<Vec<u8>> for Value<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self::Blob(value.into())
    }
}

impl Value<'_> {
    pub fn into_string(self) -> String {
        match self {
            Value::Text(s) => s.into_owned(),
            Value::Integer(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Blob(b) => String::from_utf8_lossy(b.as_ref()).into_owned(),
            Value::Null => "".into(),
        }
    }

    pub fn into_lower_string(self) -> String {
        match self {
            Value::Text(s) => s.as_ref().to_lowercase(),
            Value::Integer(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Blob(b) => String::from_utf8_lossy(b.as_ref()).to_lowercase(),
            Value::Null => "".into(),
        }
    }
}

impl From<Row> for Vec<String> {
    fn from(value: Row) -> Self {
        value.values.into_iter().map(|v| v.into_string()).collect()
    }
}

impl From<Row> for Vec<u32> {
    fn from(value: Row) -> Self {
        value
            .values
            .into_iter()
            .filter_map(|v| {
                if let Value::Integer(v) = v {
                    Some(v as u32)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl From<Rows> for Vec<String> {
    fn from(value: Rows) -> Self {
        value
            .rows
            .into_iter()
            .flat_map(|v| v.values.into_iter().map(|v| v.into_string()))
            .collect()
    }
}

impl From<Rows> for Vec<u32> {
    fn from(value: Rows) -> Self {
        value
            .rows
            .into_iter()
            .flat_map(|v| {
                v.values.into_iter().filter_map(|v| {
                    if let Value::Integer(v) = v {
                        Some(v as u32)
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

impl Store {
    #[inline(always)]
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    #[inline(always)]
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn is_same(&self, other: &Store) -> bool {
        match (self, other) {
            #[cfg(feature = "sqlite")]
            (Store::SQLite(a), Store::SQLite(b)) => Arc::ptr_eq(a, b),
            #[cfg(feature = "foundation")]
            (Store::FoundationDb(a), Store::FoundationDb(b)) => Arc::ptr_eq(a, b),
            #[cfg(feature = "postgres")]
            (Store::PostgreSQL(a), Store::PostgreSQL(b)) => Arc::ptr_eq(a, b),
            #[cfg(feature = "mysql")]
            (Store::MySQL(a), Store::MySQL(b)) => Arc::ptr_eq(a, b),
            #[cfg(feature = "rocks")]
            (Store::RocksDb(a), Store::RocksDb(b)) => Arc::ptr_eq(a, b),
            (Store::Ephemeral(a), Store::Ephemeral(b)) => Arc::ptr_eq(a, b),
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            (Store::SQLReadReplica(a), Store::SQLReadReplica(b)) => Arc::ptr_eq(a, b),
            (Store::None, Store::None) => true,
            _ => false,
        }
    }

    #[inline(always)]
    pub fn is_sql(&self) -> bool {
        match self {
            #[cfg(feature = "sqlite")]
            Store::SQLite(_) => true,
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(_) => true,
            #[cfg(feature = "mysql")]
            Store::MySQL(_) => true,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Store::SQLReadReplica(_) => true,
            // SPDX-SnippetEnd
            _ => false,
        }
    }

    #[inline(always)]
    pub fn is_pg_or_mysql(&self) -> bool {
        match self {
            #[cfg(feature = "mysql")]
            Store::MySQL(_) => true,
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(_) => true,
            _ => false,
        }
    }

    #[inline(always)]
    pub fn is_foundationdb(&self) -> bool {
        match self {
            #[cfg(feature = "foundation")]
            Store::FoundationDb(_) => true,
            _ => false,
        }
    }

    #[inline(always)]
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral(_))
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn downgrade_store(self) -> Self {
        match self {
            #[cfg(any(feature = "postgres", feature = "mysql"))]
            Store::SQLReadReplica(store) => store.primary_store().clone(),
            other => other,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn is_enterprise(&self) -> bool {
        match self {
            #[cfg(any(feature = "postgres", feature = "mysql"))]
            Store::SQLReadReplica(_) => true,
            _ => false,
        }
    }
    // SPDX-SnippetEnd
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(_) => f.debug_tuple("SQLite").finish(),
            #[cfg(feature = "foundation")]
            Self::FoundationDb(_) => f.debug_tuple("FoundationDb").finish(),
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(_) => f.debug_tuple("PostgreSQL").finish(),
            #[cfg(feature = "mysql")]
            Self::MySQL(_) => f.debug_tuple("MySQL").finish(),
            #[cfg(feature = "rocks")]
            Self::RocksDb(_) => f.debug_tuple("RocksDb").finish(),
            Self::Ephemeral(_) => f.debug_tuple("Ephemeral").finish(),

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(_) => f.debug_tuple("SQLReadReplica").finish(),
            // SPDX-SnippetEnd
            Self::None => f.debug_tuple("None").finish(),
        }
    }
}

impl From<Value<'_>> for trc::Value {
    fn from(value: Value) -> Self {
        match value {
            Value::Integer(v) => trc::Value::Int(v),
            Value::Bool(v) => trc::Value::Bool(v),
            Value::Float(v) => trc::Value::Float(v),
            Value::Text(v) => trc::Value::String(match v {
                Cow::Borrowed(v) => v.into(),
                Cow::Owned(v) => v.into(),
            }),
            Value::Blob(v) => trc::Value::Bytes(v.into_owned()),
            Value::Null => trc::Value::None,
        }
    }
}

impl From<Value<'static>> for () {
    fn from(_: Value<'static>) -> Self {
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::Subspace;

    #[test]
    fn subspace_byte_roundtrip() {
        for subspace in Subspace::ALL.iter().copied() {
            assert_eq!(Subspace::try_from_byte(subspace.byte()), Some(subspace));
        }
    }
}
