/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use crate::auth::{AccessTokenInner, EmailAddress, TokenScope};
use crate::manager::application::WebApplications;
use crate::network::asn::AsnGeoLookupData;
use crate::network::memory::MemoryBudget;
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::auth::TenantCache;
// SPDX-SnippetEnd
use crate::{
    auth::{AccountCache, DomainCache, EmailCache, MailingListCache, RoleCache},
    cache::{
        email::{IdIndex, ThreadRange},
        http_auth::{GrantRevocations, HttpAuthEntries},
        large::{LargeMessageCaches, LargeResourceCaches},
        swap::evict::SwapEviction,
    },
    config::{
        mailstore::{
            email::EmailConfig,
            imap::ImapConfig,
            scripts::Scripting,
            spamfilter::{SpamClassifier, SpamFilterConfig, SpamLookup},
        },
        smtp::auth::DkimSigners,
    },
    ipc::TrainTaskController,
    network::security::BlockedIps,
    storage::metadata::MetadataViewerCache,
};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use auth::oauth::config::OAuthConfig;
use calcard::common::timezone::Tz;
use compact_str::CompactString;
use config::{
    groupware::GroupwareConfig,
    mailstore::jmap::JmapConfig,
    metadata::MetadataConfig,
    network::Network,
    smtp::{
        SmtpConfig,
        resolver::{MtaStsEntry, Tlsa},
    },
    storage::Storage,
    telemetry::Metrics,
};
use gateway::resolver::{KeyCacheKey, KeyEntry};
use ipc::{BroadcastEvent, PushEvent, QueueEvent, ReportingEvent, subscribers::PushSubscribers};
use mail_auth::{Mx, Negative, RecordSet, TxtRecord};
use parking_lot::{Mutex, RwLock};
use rustls::sign::CertifiedKey;
use std::sync::atomic::AtomicU64;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, OnceLock, Weak, atomic::AtomicBool},
    time::Duration,
};
use store::InMemoryStore;
use tinyvec::TinyVec;
use tokio::sync::{Notify, OnceCell, Semaphore, mpsc};
use tokio_rustls::TlsConnector;
use types::{acl::AclGrant, metadata::MetadataKinds, special_use::SpecialUse};
use utils::{
    cache::{Cache, CacheWithTtl, SpillCache},
    snowflake::SnowflakeIdGenerator,
};

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use bytes::Bytes;
#[cfg(feature = "enterprise")]
use manager::application::Resource;
// SPDX-SnippetEnd

pub mod auth;
pub mod cache;
pub mod config;
pub mod expr;
pub mod gateway;
pub mod i18n;
pub mod ipc;
pub mod manager;
pub mod network;
pub mod scripts;
pub mod sharing;
pub mod storage;
pub mod telemetry;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL

#[cfg(feature = "enterprise")]
pub mod enterprise;

// SPDX-SnippetEnd

pub use psl;

pub static VERSION_PRIVATE: &str = env!("CARGO_PKG_VERSION");
pub static VERSION_PUBLIC: &str = "1.0.0";

pub static USER_AGENT: &str = "Stalwart/1.0.0";
pub static DAEMON_NAME: &str = concat!("Stalwart v", env!("CARGO_PKG_VERSION"),);
pub static PROD_ID: &str = "-//Stalwart Labs LLC//Stalwart Server//EN";

/*

Schema history:

1 - v0.12.0
2 - v0.12.4
3 - v0.13.0
4 - v0.14.0
5 - v0.15.0
6 - v0.16.0
7 - v1.0.0

*/

pub const DATABASE_SCHEMA_VERSION_BASE: u32 = 7;
pub const DATABASE_SCHEMA_OSS_FLAG: u32 = 1 << 31;

#[cfg(feature = "enterprise")]
pub const DATABASE_SCHEMA_VERSION: u32 = DATABASE_SCHEMA_VERSION_BASE;
#[cfg(not(feature = "enterprise"))]
pub const DATABASE_SCHEMA_VERSION: u32 = DATABASE_SCHEMA_VERSION_BASE | DATABASE_SCHEMA_OSS_FLAG;

pub const LONG_1D_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24);
pub const LONG_1Y_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24 * 365);

pub const IPC_CHANNEL_BUFFER: usize = 1024;

pub const KV_ACME: u8 = 0;
pub const KV_OAUTH: u8 = 1;
pub const KV_RATE_LIMIT_RCPT: u8 = 2;
pub const KV_RATE_LIMIT_SCAN: u8 = 3;
pub const KV_RATE_LIMIT_LOITER: u8 = 4;
pub const KV_RATE_LIMIT_AUTH: u8 = 5;
pub const KV_RATE_LIMIT_SMTP: u8 = 6;
pub const KV_RATE_LIMIT_CONTACT: u8 = 7;
pub const KV_RATE_LIMIT_HTTP_AUTHENTICATED: u8 = 8;
pub const KV_RATE_LIMIT_HTTP_ANONYMOUS: u8 = 9;
pub const KV_RATE_LIMIT_IMAP: u8 = 10;
pub const KV_QUOTA_BLOB: u8 = 11;
pub const KV_RATE_LIMIT_AVAILABILITY: u8 = 12;
pub const KV_GREYLIST: u8 = 13;
pub const KV_LOCK_QUEUE_MESSAGE: u8 = 14;
pub const KV_LOCK_TASK: u8 = 15;
pub const KV_LOCK_DAV: u8 = 16;
pub const KV_LOCK_SEARCH_INDEX: u8 = 17;
pub const KV_OAUTH_CIMD: u8 = 18;
pub const KV_RATE_LIMIT_CIMD: u8 = 19;
pub const KV_KEY_LOOKUP: u8 = 20;

#[derive(Clone)]
pub struct Server {
    pub inner: Arc<Inner>,
    pub core: Arc<Core>,
}

pub struct Inner {
    pub shared_core: ArcSwap<Core>,
    pub data: Data,
    pub cache: Caches,
    pub ipc: Ipc,
}

#[allow(clippy::type_complexity)]
pub struct Data {
    pub spam_classifier: ArcSwap<SpamClassifier>,

    pub tls_certificates: ArcSwap<AHashMap<Box<str>, Arc<CertifiedKey>>>,
    pub tls_self_signed_cert: Option<Arc<CertifiedKey>>,

    pub blocked_ips: RwLock<BlockedIps>,
    pub lookup_stores: ArcSwap<AHashMap<Box<str>, InMemoryStore>>,

    pub asn_geo_data: AsnGeoLookupData,
    pub password_verifier: directory::core::verifier::PasswordVerifier,

    pub jmap_id_gen: SnowflakeIdGenerator,
    pub queue_id_gen: SnowflakeIdGenerator,
    pub span_id_gen: SnowflakeIdGenerator,
    pub registry_id_gen: SnowflakeIdGenerator,
    pub queue_status: AtomicBool,

    pub applications: WebApplications,
    pub logos: Mutex<AHashMap<Box<str>, LogoCache>>,

    pub smtp_connectors: TlsConnectors,
    pub memory_budget: MemoryBudget,

    pub harvest_tasks: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct LogoCache {
    domain_id: u32,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    tenant_id: Option<u32>,
    #[cfg(feature = "enterprise")]
    data: Option<Resource<Bytes>>,
    // SPDX-SnippetEnd
}

pub struct Caches {
    pub swap: crate::cache::swap::SwapTier,
    pub revalidate: crate::cache::RevalidateInterval,

    pub access_tokens: SpillCache<u32, Arc<AccessTokenInner>>,
    pub http_auth: HttpAuthEntries,
    pub grant_revocations: GrantRevocations,

    pub messages: Cache<u32, Arc<MessageStoreCache>, SwapEviction>,
    pub messages_large: LargeMessageCaches,
    pub resources_large: LargeResourceCaches,
    pub files: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub contacts: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub events: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub scheduling: Cache<u32, Arc<GroupwareResources>, SwapEviction>,
    pub metadata_viewers: MetadataViewerCache,

    pub emails: Cache<EmailAddress, EmailCache>,
    pub emails_negative: CacheWithTtl<EmailAddress, ()>,
    pub domain_names: Cache<CompactString, u32>,
    pub domain_names_negative: CacheWithTtl<CompactString, ()>,

    pub domains: Cache<u32, Arc<DomainCache>>,
    pub accounts: Cache<u32, Arc<AccountCache>>,
    pub roles: Cache<u32, Arc<RoleCache>>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub tenants: Cache<u32, Arc<TenantCache>>,
    // SPDX-SnippetEnd
    pub lists: Cache<u32, Arc<MailingListCache>>,

    pub dkim_signers: Cache<u32, Arc<DkimSigners>>,
    pub external_public_keys: CacheWithTtl<KeyCacheKey, Option<Arc<KeyEntry>>>,

    pub dns_txt: CacheWithTtl<Box<str>, TxtRecord>,
    pub dns_mx: CacheWithTtl<Box<str>, Result<RecordSet<Mx>, Negative>>,
    pub dns_ptr: CacheWithTtl<IpAddr, Result<RecordSet<Box<str>>, Negative>>,
    pub dns_ipv4: CacheWithTtl<Box<str>, Result<RecordSet<Ipv4Addr>, Negative>>,
    pub dns_ipv6: CacheWithTtl<Box<str>, Result<RecordSet<Ipv6Addr>, Negative>>,
    pub dns_tlsa: CacheWithTtl<Box<str>, Option<Arc<Tlsa>>>,
    pub dns_mta_sts: CacheWithTtl<Box<str>, MtaStsEntry>,
    pub spam_lookup: CacheWithTtl<Box<str>, SpamLookup>,

    pub directory_recipients: CacheWithTtl<Box<str>, ()>,
    pub directory_recipients_ttl: Duration,

    pub negative_cache_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct MessageStoreCache {
    pub emails: Arc<MessagesCache>,
    pub mailboxes: Arc<MailboxesCache>,
    pub update_lock: Arc<MessageUpdateLock>,
    pub refresh: Arc<RefreshState>,
    pub last_change_id: u64,
    pub size: u64,
    pub verification: Verification,
}

#[derive(Debug, Default)]
pub struct RefreshState {
    pub deltas: Box<[ItemDelta]>,
    pub uid_next: UidNextMemo,
    pub mailbox_rows: Arc<MailboxRowsMemo>,
}

#[derive(Debug, Clone)]
pub struct ItemDelta {
    pub from_change_id: u64,
    pub to_change_id: u64,
    pub document_ids: Arc<[u32]>,
}

#[derive(Debug, Default)]
pub struct UidNextMemo {
    values: Mutex<Vec<(u32, Arc<OnceCell<u32>>)>>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MailboxRow {
    pub uid: u32,
    pub id: u32,
}

#[derive(Debug, Default)]
pub struct MailboxRowsMemo {
    entries: Mutex<Vec<SharedMailboxRows>>,
}

#[derive(Debug)]
struct SharedMailboxRows {
    mailbox_id: u32,
    emails: Weak<MessagesCache>,
    rows: Arc<Vec<MailboxRow>>,
}

#[derive(Debug, Clone)]
pub struct MailboxesCache {
    pub change_id: u64,
    pub index: AHashMap<u32, u32>,
    pub items: Box<[MailboxCache]>,
    pub size: u64,
}

pub const CACHE_CHUNK: usize = 16384;

pub const MAX_RECEIVED_AT: u64 = u32::MAX as u64;

#[derive(Debug, Clone)]
pub struct ColBlock {
    pub(crate) document_ids: Arc<[u32]>,
    pub(crate) change_ids: Arc<[u64]>,
    pub(crate) received_at: Arc<[u32]>,
    pub(crate) sent_at: Arc<[i32]>,
    pub(crate) sizes: Arc<[u32]>,
    pub(crate) keywords: Arc<[u32]>,
    pub(crate) thread_ids: Arc<[u32]>,
    pub(crate) thread_range: ThreadRange,
    pub(crate) mb_offsets: Arc<[u32]>,
    pub(crate) mb_arena: Arc<[MessageUid]>,
}

#[derive(Debug, Clone)]
pub struct MessagesCache {
    pub change_id: u64,
    pub(crate) blocks: Vec<Arc<ColBlock>>,
    pub(crate) starts: Vec<u32>,
    pub(crate) index: IdIndex,
    pub(crate) keywords: Arc<[CustomKeywords]>,
    pub(crate) len: usize,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct CustomKeywords {
    pub names: Box<[CompactString]>,
    pub document_id: u32,
}

#[derive(Debug, Clone)]
pub struct MessageCache {
    pub(crate) document_id: u32,
    pub(crate) mailboxes: TinyVec<[MessageUid; 2]>,
    pub(crate) keywords: u32,
    pub(crate) thread_id: u32,
    pub(crate) change_id: u64,
    pub(crate) size: u32,
    pub(crate) received_at: u64,
    pub(crate) sent_at: i32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MessageUid {
    pub mailbox_id: u32,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct MailboxCache {
    pub document_id: u32,
    pub name: Arc<str>,
    pub path: Arc<str>,
    pub role: SpecialUse,
    pub parent_id: u32,
    pub sort_order: u32,
    pub subscribers: TinyVec<[u32; 4]>,
    pub uid_validity: u32,
    pub acls: TinyVec<[AclGrant; 2]>,
    pub metadata_kinds: MetadataKinds,
}

const _: () = assert!(size_of::<MailboxCache>() <= 136);

#[derive(Debug, Clone)]
pub struct HttpAuthCache {
    pub account_id: u32,
    pub expires: u32,
    pub credential_id: Option<u32>,
    pub revision: u64,
    pub token_scope: Option<TokenScope>,
}

const _: () = assert!(size_of::<HttpAuthCache>() <= 40);

pub struct Ipc {
    pub push_tx: mpsc::Sender<PushEvent>,
    pub push_subscribers: Arc<PushSubscribers>,
    pub task_tx: ipc::TaskQueueNotify,
    pub index_tx: Arc<Notify>,
    pub queue_tx: mpsc::Sender<QueueEvent>,
    pub report_tx: mpsc::Sender<ReportingEvent>,
    pub broadcast_tx: Option<mpsc::Sender<BroadcastEvent>>,
    pub train_task_controller: Arc<TrainTaskController>,
}

impl Ipc {
    pub fn index_queue_notify(&self) -> ipc::IndexQueueNotify {
        ipc::IndexQueueNotify::new(self.index_tx.clone(), self.broadcast_tx.clone())
    }
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
}

pub struct NameWrapper(pub String);

#[derive(Debug)]
pub struct UpdateLock {
    pub semaphore: Semaphore,
    pub revision: AtomicU64,
    pub epoch: AtomicU64,
}

#[derive(Debug, Default)]
pub struct MessageUpdateLock {
    is_updating: AtomicBool,
    released: Notify,
    epoch: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Verification {
    verified_at: u64,
    epoch: u64,
}

pub const DAV_CHUNK: usize = 4096;
pub const NO_ID: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaRef {
    pub off: u32,
    pub len: u32,
}

impl ArenaRef {
    #[inline(always)]
    pub fn range(&self) -> std::ops::Range<usize> {
        self.off as usize..(self.off as usize + self.len as usize)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug, Clone)]
pub struct GroupwareResources {
    pub base_path: String,
    pub paths: Arc<PathIndex>,
    pub resources: ResourceStore,
    pub item_change_id: u64,
    pub container_change_id: u64,
    pub highest_change_id: u64,
    pub size: u64,
    pub update_lock: Arc<UpdateLock>,
    pub verification: Verification,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceStore {
    pub chunks: Vec<Arc<ResourceChunk>>,
    pub containers_end: usize,
    pub total: usize,
    pub unified_id_space: bool,
}

#[derive(Debug, Default)]
pub struct ResourceChunk {
    pub records: Box<[GroupwareResource]>,
    pub bytes: Box<[u8]>,
    pub names: Box<[CachedName]>,
    pub acls: Box<[AclGrant]>,
    pub prefs: Box<[TinyCalendarPreferences]>,
    pub principals: Box<[u32]>,
    pub uid_index: OnceLock<Box<[u64]>>,
    pub min_id: u32,
    pub max_id: u32,
}

#[derive(Debug, Clone, Default)]
pub struct PathIndex {
    pub chunks: Vec<Arc<PathChunk>>,
    pub total: usize,
}

#[derive(Debug, Default)]
pub struct PathChunk {
    pub paths: Box<[DavPath]>,
    pub bytes: Box<[u8]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CachedName {
    pub name: ArenaRef,
    pub parent_id: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DavPath {
    pub path: ArenaRef,
    pub parent_id: u32,
    pub hierarchy_seq: u32,
    pub document_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupwareResource {
    pub document_id: u32,
    pub data: GroupwareResourceMetadata,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupwareResourceRef<'x> {
    pub chunk: &'x ResourceChunk,
    pub resource: &'x GroupwareResource,
}

#[derive(Debug, Clone, Copy)]
pub struct DavResourcePath<'x> {
    pub path: &'x DavPath,
    pub path_chunk: &'x PathChunk,
    pub resource: GroupwareResourceRef<'x>,
}

#[derive(Debug, Clone, Copy)]
pub enum GroupwareResourceMetadata {
    File {
        name: ArenaRef,
        size: u32,
        parent_id: u32,
        acls: ArenaRef,
        etag: u32,
        modified: i64,
        created_delta: i32,
        flags: FileFlags,
    },
    Calendar {
        name: ArenaRef,
        acls: ArenaRef,
        preferences: ArenaRef,
        etag: u32,
        metadata: MetadataKinds,
    },
    CalendarEvent {
        names: ArenaRef,
        start: i64,
        duration: u32,
        created_at: i64,
        modified_at: i32,
        uid: ArenaRef,
        etag: u32,
        flags: u16,
    },
    CalendarEventNotification {
        names: ArenaRef,
        created_at: i64,
        event_id: u32,
        etag: u32,
        changed_by: u32,
        principals: ArenaRef,
        calendar_ids_len: u16,
        flags: u16,
    },
    AddressBook {
        name: ArenaRef,
        acls: ArenaRef,
        etag: u32,
        metadata: MetadataKinds,
    },
    ContactCard {
        names: ArenaRef,
        created_at: i64,
        modified_at: i32,
        uid: ArenaRef,
        etag: u32,
        flags: u16,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileFlags(pub u32);

#[derive(Debug, Clone, Copy, Default)]
pub struct TinyCalendarPreferences {
    pub account_id: u32,
    pub tz: Tz,
    pub flags: u16,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct DavName {
    pub name: String,
    pub parent_id: u32,
}

#[derive(Clone)]
pub struct Core {
    pub storage: Storage,
    pub sieve: Scripting,
    pub network: Network,
    pub oauth: OAuthConfig,
    pub email: EmailConfig,
    pub jmap: JmapConfig,
    pub imap: ImapConfig,
    pub smtp: SmtpConfig,
    pub spam: SpamFilterConfig,
    pub groupware: GroupwareConfig,
    pub metadata: MetadataConfig,
    pub metrics: Metrics,

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub enterprise: Option<enterprise::Enterprise>,
    // SPDX-SnippetEnd
}

pub trait BuildServer {
    fn build_server(&self) -> Server;
}

impl BuildServer for Arc<Inner> {
    fn build_server(&self) -> Server {
        Server {
            inner: self.clone(),
            core: self.shared_core.load_full(),
        }
    }
}

pub trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ThrottleKey {
    pub hash: [u8; 32],
}

impl MessageUid {
    pub fn new(mailbox_id: u32, uid: u32) -> Self {
        MessageUid { mailbox_id, uid }
    }

    pub fn new_unassigned(mailbox_id: u32) -> Self {
        MessageUid { mailbox_id, uid: 0 }
    }
}

pub const DEFAULT_LOGO_BASE64: &str = "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";
