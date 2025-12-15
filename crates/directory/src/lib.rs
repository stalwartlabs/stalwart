/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use ahash::AHashMap;
use backend::{
    imap::{ImapDirectory, ImapError},
    ldap::LdapDirectory,
    memory::MemoryDirectory,
    smtp::SmtpDirectory,
    sql::SqlDirectory,
};
use core::cache::CachedDirectory;
use deadpool::managed::PoolError;
use ldap3::LdapError;
use mail_send::Credentials;
use proc_macros::EnumMethods;
use std::{fmt::Debug, sync::Arc};
use store::Store;
use trc::ipc::bitset::Bitset;
use types::collection::Collection;

pub mod backend;
pub mod core;

pub struct Directory {
    pub store: DirectoryInner,
    pub cache: Option<CachedDirectory>,
}

pub const FALLBACK_ADMIN_ID: u32 = u32::MAX;

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: u32,
    pub typ: Type,
    pub name: String,
    pub data: Vec<PrincipalData>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrincipalData {
    Password(String),

    // Permissions and memberships
    Tenant(u32),
    MemberOf(u32),
    Role(u32),
    List(u32),
    Permission { permission_id: u32, grant: bool },

    // Quotas
    DiskQuota(u64),
    DirectoryQuota { quota: u32, typ: Type },
    ObjectQuota { quota: u32, typ: Collection },

    // Profile data
    Description(String),
    PrimaryEmail(String),
    EmailAlias(String),
    Picture(String),
    ExternalMember(String),
    Url(String),
    Locale(String),

    // Secrets
    AppPassword(String),
    OtpAuth(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrant {
    pub permission: Permission,
    pub grant: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberOf {
    pub principal_id: u32,
    pub typ: Type,
}

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Hash,
)]
#[serde(rename_all = "camelCase")]
pub enum Type {
    #[default]
    Individual = 0,
    Group = 1,
    Resource = 2,
    Location = 3,
    List = 5,
    Other = 6,
    Domain = 7,
    Tenant = 8,
    Role = 9,
    ApiKey = 10,
    OauthClient = 11,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, EnumMethods,
)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    // WARNING: add new ids at the end (TODO: use static ids)

    // Admin
    Impersonate,
    UnlimitedRequests,
    UnlimitedUploads,
    DeleteSystemFolders_,
    MessageQueueList,
    MessageQueueGet,
    MessageQueueUpdate,
    MessageQueueDelete,
    OutgoingReportList,
    OutgoingReportGet,
    OutgoingReportDelete,
    IncomingReportList,
    IncomingReportGet,
    IncomingReportDelete,
    SettingsList,
    SettingsUpdate,
    SettingsDelete,
    SettingsReload,
    IndividualList,
    IndividualGet,
    IndividualUpdate,
    IndividualDelete,
    IndividualCreate,
    GroupList,
    GroupGet,
    GroupUpdate,
    GroupDelete,
    GroupCreate,
    DomainList,
    DomainGet,
    DomainCreate,
    DomainUpdate,
    DomainDelete,
    TenantList,
    TenantGet,
    TenantCreate,
    TenantUpdate,
    TenantDelete,
    MailingListList,
    MailingListGet,
    MailingListCreate,
    MailingListUpdate,
    MailingListDelete,
    RoleList,
    RoleGet,
    RoleCreate,
    RoleUpdate,
    RoleDelete,
    PrincipalList,
    PrincipalGet,
    PrincipalCreate,
    PrincipalUpdate,
    PrincipalDelete,
    BlobFetch,
    PurgeBlobStore,
    PurgeDataStore,
    PurgeInMemoryStore,
    PurgeAccount,
    FtsReindex,
    Undelete,
    DkimSignatureCreate,
    DkimSignatureGet,
    SpamFilterUpdate,
    WebadminUpdate,
    LogsView,
    SpamFilterTrain,
    Restart,
    TracingList,
    TracingGet,
    TracingLive,
    MetricsList,
    MetricsLive,

    // Generic
    Authenticate,
    AuthenticateOauth,
    EmailSend,
    EmailReceive,

    // Account Management
    ManageEncryption,
    ManagePasswords,

    // JMAP
    JmapEmailGet,
    JmapMailboxGet,
    JmapThreadGet,
    JmapIdentityGet,
    JmapEmailSubmissionGet,
    JmapPushSubscriptionGet,
    JmapSieveScriptGet,
    JmapVacationResponseGet,
    JmapPrincipalGet,
    JmapQuotaGet,
    JmapBlobGet,
    JmapEmailSet,
    JmapMailboxSet,
    JmapIdentitySet,
    JmapEmailSubmissionSet,
    JmapPushSubscriptionSet,
    JmapSieveScriptSet,
    JmapVacationResponseSet,
    JmapEmailChanges,
    JmapMailboxChanges,
    JmapThreadChanges,
    JmapIdentityChanges,
    JmapEmailSubmissionChanges,
    JmapQuotaChanges,
    JmapEmailCopy,
    JmapBlobCopy,
    JmapEmailImport,
    JmapEmailParse,
    JmapEmailQueryChanges,
    JmapMailboxQueryChanges,
    JmapEmailSubmissionQueryChanges,
    JmapSieveScriptQueryChanges,
    JmapPrincipalQueryChanges,
    JmapQuotaQueryChanges,
    JmapEmailQuery,
    JmapMailboxQuery,
    JmapEmailSubmissionQuery,
    JmapSieveScriptQuery,
    JmapPrincipalQuery,
    JmapQuotaQuery,
    JmapSearchSnippet,
    JmapSieveScriptValidate,
    JmapBlobLookup,
    JmapBlobUpload,
    JmapEcho,

    // IMAP
    ImapAuthenticate,
    ImapAclGet,
    ImapAclSet,
    ImapMyRights,
    ImapListRights,
    ImapAppend,
    ImapCapability,
    ImapId,
    ImapCopy,
    ImapMove,
    ImapCreate,
    ImapDelete,
    ImapEnable,
    ImapExpunge,
    ImapFetch,
    ImapIdle,
    ImapList,
    ImapLsub,
    ImapNamespace,
    ImapRename,
    ImapSearch,
    ImapSort,
    ImapSelect,
    ImapExamine,
    ImapStatus,
    ImapStore,
    ImapSubscribe,
    ImapThread,

    // POP3
    Pop3Authenticate,
    Pop3List,
    Pop3Uidl,
    Pop3Stat,
    Pop3Retr,
    Pop3Dele,

    // ManageSieve
    SieveAuthenticate,
    SieveListScripts,
    SieveSetActive,
    SieveGetScript,
    SievePutScript,
    SieveDeleteScript,
    SieveRenameScript,
    SieveCheckScript,
    SieveHaveSpace,

    // API keys
    ApiKeyList,
    ApiKeyGet,
    ApiKeyCreate,
    ApiKeyUpdate,
    ApiKeyDelete,

    // OAuth clients
    OauthClientList,
    OauthClientGet,
    OauthClientCreate,
    OauthClientUpdate,
    OauthClientDelete,

    // OAuth client registration
    OauthClientRegistration,
    OauthClientOverride,

    AiModelInteract,
    Troubleshoot,
    SpamFilterTest,

    // WebDAV permissions
    DavSyncCollection,
    DavExpandProperty,

    DavPrincipalAcl,
    DavPrincipalList,
    DavPrincipalMatch,
    DavPrincipalSearch,
    DavPrincipalSearchPropSet,

    DavFilePropFind,
    DavFilePropPatch,
    DavFileGet,
    DavFileMkCol,
    DavFileDelete,
    DavFilePut,
    DavFileCopy,
    DavFileMove,
    DavFileLock,
    DavFileAcl,

    DavCardPropFind,
    DavCardPropPatch,
    DavCardGet,
    DavCardMkCol,
    DavCardDelete,
    DavCardPut,
    DavCardCopy,
    DavCardMove,
    DavCardLock,
    DavCardAcl,
    DavCardQuery,
    DavCardMultiGet,

    DavCalPropFind,
    DavCalPropPatch,
    DavCalGet,
    DavCalMkCol,
    DavCalDelete,
    DavCalPut,
    DavCalCopy,
    DavCalMove,
    DavCalLock,
    DavCalAcl,
    DavCalQuery,
    DavCalMultiGet,
    DavCalFreeBusyQuery,

    CalendarAlarms,
    CalendarSchedulingSend,
    CalendarSchedulingReceive,

    JmapAddressBookGet,
    JmapAddressBookSet,
    JmapAddressBookChanges,

    JmapContactCardGet,
    JmapContactCardChanges,
    JmapContactCardQuery,
    JmapContactCardQueryChanges,
    JmapContactCardSet,
    JmapContactCardCopy,
    JmapContactCardParse,

    JmapFileNodeGet,
    JmapFileNodeSet,
    JmapFileNodeChanges,
    JmapFileNodeQuery,
    JmapFileNodeQueryChanges,

    JmapPrincipalGetAvailability,
    JmapPrincipalChanges,

    JmapShareNotificationGet,
    JmapShareNotificationSet,
    JmapShareNotificationChanges,
    JmapShareNotificationQuery,
    JmapShareNotificationQueryChanges,

    JmapCalendarGet,
    JmapCalendarSet,
    JmapCalendarChanges,

    JmapCalendarEventGet,
    JmapCalendarEventSet,
    JmapCalendarEventChanges,
    JmapCalendarEventQuery,
    JmapCalendarEventQueryChanges,
    JmapCalendarEventCopy,
    JmapCalendarEventParse,

    JmapCalendarEventNotificationGet,
    JmapCalendarEventNotificationSet,
    JmapCalendarEventNotificationChanges,
    JmapCalendarEventNotificationQuery,
    JmapCalendarEventNotificationQueryChanges,

    JmapParticipantIdentityGet,
    JmapParticipantIdentitySet,
    JmapParticipantIdentityChanges,
    // TODO: Reuse _ suffixes for new permissions
    // WARNING: add new ids at the end (TODO: use static ids)
}

pub const PERMISSIONS_BITSET_SIZE: usize = Permission::COUNT.div_ceil(std::mem::size_of::<u32>());
pub type Permissions = Bitset<PERMISSIONS_BITSET_SIZE>;

pub const ROLE_ADMIN: u32 = u32::MAX;
pub const ROLE_TENANT_ADMIN: u32 = u32::MAX - 1;
pub const ROLE_USER: u32 = u32::MAX - 2;

pub enum DirectoryInner {
    Internal(Store),
    Ldap(LdapDirectory),
    Sql(SqlDirectory),
    OpenId(backend::oidc::OpenIdDirectory),
    Imap(ImapDirectory),
    Smtp(SmtpDirectory),
    Memory(MemoryDirectory),
}

pub enum QueryBy<'x> {
    Name(&'x str),
    Id(u32),
    Credentials(&'x Credentials<String>),
}

pub struct QueryParams<'x> {
    pub by: QueryBy<'x>,
    pub return_member_of: bool,
    pub only_app_pass: bool,
}

impl Default for Directory {
    fn default() -> Self {
        Self {
            store: DirectoryInner::Internal(Store::None),
            cache: None,
        }
    }
}

impl Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory").finish()
    }
}

#[derive(Default, Clone, Debug)]
pub struct Directories {
    pub directories: AHashMap<String, Arc<Directory>>,
}

trait IntoError {
    fn into_error(self) -> trc::Error;
}

impl IntoError for PoolError<LdapError> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .into_err()
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError.reason(err),
        }
    }
}

impl IntoError for PoolError<ImapError> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .into_err()
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError.reason(err),
        }
    }
}

impl IntoError for PoolError<mail_send::Error> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .into_err()
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError.reason(err),
        }
    }
}

impl IntoError for ImapError {
    fn into_error(self) -> trc::Error {
        trc::ImapEvent::Error.into_err().reason(self)
    }
}

impl IntoError for mail_send::Error {
    fn into_error(self) -> trc::Error {
        trc::SmtpEvent::Error.into_err().reason(self)
    }
}

impl IntoError for LdapError {
    fn into_error(self) -> trc::Error {
        if let LdapError::LdapResult { result } = &self {
            trc::StoreEvent::LdapError
                .ctx(trc::Key::Code, result.rc)
                .reason(self)
        } else {
            trc::StoreEvent::LdapError.reason(self)
        }
    }
}

impl From<&ArchivedType> for Type {
    fn from(archived: &ArchivedType) -> Self {
        match archived {
            ArchivedType::Individual => Type::Individual,
            ArchivedType::Group => Type::Group,
            ArchivedType::Resource => Type::Resource,
            ArchivedType::Location => Type::Location,
            ArchivedType::List => Type::List,
            ArchivedType::Other => Type::Other,
            ArchivedType::Domain => Type::Domain,
            ArchivedType::Tenant => Type::Tenant,
            ArchivedType::Role => Type::Role,
            ArchivedType::ApiKey => Type::ApiKey,
            ArchivedType::OauthClient => Type::OauthClient,
        }
    }
}

impl<'x> QueryParams<'x> {
    pub fn name(name: &'x str) -> Self {
        QueryParams {
            by: QueryBy::Name(name),
            return_member_of: false,
            only_app_pass: false,
        }
    }

    pub fn credentials(credentials: &'x Credentials<String>) -> Self {
        QueryParams {
            by: QueryBy::Credentials(credentials),
            return_member_of: false,
            only_app_pass: false,
        }
    }

    pub fn id(id: u32) -> Self {
        QueryParams {
            by: QueryBy::Id(id),
            return_member_of: false,
            only_app_pass: false,
        }
    }

    pub fn by(by: QueryBy<'x>) -> Self {
        QueryParams {
            by,
            return_member_of: false,
            only_app_pass: false,
        }
    }

    pub fn with_return_member_of(mut self, return_member_of: bool) -> Self {
        self.return_member_of = return_member_of;
        self
    }

    pub fn with_only_app_pass(mut self, only_app_pass: bool) -> Self {
        self.only_app_pass = only_app_pass;
        self
    }
}
