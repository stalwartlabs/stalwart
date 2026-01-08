/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    addressbook_v2::migrate_addressbook_v013,
    calendar_v2::migrate_calendar_v013,
    contact_v2::migrate_contacts_v013,
    event_v2::{migrate_calendar_events_v013, migrate_calendar_scheduling_v013},
    get_document_ids,
    push_v2::migrate_push_subscriptions_v013,
    sieve_v2::migrate_sieve_v013,
};
use common::Server;
use directory::{Principal, PrincipalData, Type, backend::internal::SpecialSecrets};
use proc_macros::EnumMethods;
use std::time::Instant;
use store::{
    Serialize, ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, DirectoryClass, ValueClass},
};
use trc::AddContext;
use types::collection::Collection;

pub(crate) async fn migrate_principals_v0_13(server: &Server) -> trc::Result<RoaringBitmap> {
    // Obtain email ids
    let principal_ids = get_document_ids(server, u32::MAX, Collection::Principal)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_principals = principal_ids.len();
    if num_principals == 0 {
        return Ok(principal_ids);
    }
    let mut num_migrated = 0;

    for principal_id in principal_ids.iter() {
        match server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey {
                account_id: u32::MAX,
                collection: Collection::Principal.into(),
                document_id: principal_id,
                class: ValueClass::Directory(DirectoryClass::Principal(principal_id)),
            })
            .await
        {
            Ok(Some(legacy)) => match legacy.deserialize_untrusted::<PrincipalV2>() {
                Ok(old_principal) => {
                    let mut principal = Principal {
                        id: principal_id,
                        typ: old_principal.typ,
                        name: old_principal.name,
                        data: Vec::new(),
                    };

                    let mut has_secret = false;
                    for secret in old_principal.secrets {
                        if secret.is_otp_secret() {
                            principal.data.push(PrincipalData::OtpAuth(secret));
                        } else if secret.is_app_secret() {
                            principal.data.push(PrincipalData::AppPassword(secret));
                        } else if !has_secret {
                            principal.data.push(PrincipalData::Password(secret));
                            has_secret = true;
                        }
                    }

                    for (idx, email) in old_principal.emails.into_iter().enumerate() {
                        if idx == 0 {
                            principal.data.push(PrincipalData::PrimaryEmail(email));
                        } else {
                            principal.data.push(PrincipalData::EmailAlias(email));
                        }
                    }

                    if let Some(description) = old_principal.description {
                        principal.data.push(PrincipalData::Description(description));
                    }

                    if let Some(quota) = old_principal.quota
                        && quota > 0
                    {
                        principal.data.push(PrincipalData::DiskQuota(quota));
                    }

                    if let Some(tenant) = old_principal.tenant {
                        principal.data.push(PrincipalData::Tenant(tenant));
                    }

                    for item in old_principal.data {
                        match item {
                            PrincipalDataV2::MemberOf(items) => {
                                for item in items {
                                    principal.data.push(PrincipalData::MemberOf(item));
                                }
                            }
                            PrincipalDataV2::Roles(items) => {
                                for item in items {
                                    principal.data.push(PrincipalData::Role(item));
                                }
                            }
                            PrincipalDataV2::Lists(items) => {
                                for item in items {
                                    principal.data.push(PrincipalData::List(item));
                                }
                            }
                            PrincipalDataV2::Permissions(items) => {
                                for item in items {
                                    principal.data.push(PrincipalData::Permission {
                                        permission_id: item.permission.id(),
                                        grant: item.grant,
                                    });
                                }
                            }
                            PrincipalDataV2::Picture(item) => {
                                principal.data.push(PrincipalData::Picture(item));
                            }
                            PrincipalDataV2::ExternalMembers(items) => {
                                for item in items {
                                    principal.data.push(PrincipalData::ExternalMember(item));
                                }
                            }
                            PrincipalDataV2::Urls(items) => {
                                for item in items {
                                    principal.data.push(PrincipalData::Url(item));
                                }
                            }
                            PrincipalDataV2::PrincipalQuota(items) => {
                                for item in items {
                                    principal.data.push(PrincipalData::DirectoryQuota {
                                        quota: item.quota as u32,
                                        typ: item.typ,
                                    });
                                }
                            }
                            PrincipalDataV2::Locale(item) => {
                                principal.data.push(PrincipalData::Locale(item));
                            }
                        }
                    }

                    principal.sort();

                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(u32::MAX)
                        .with_collection(Collection::Principal)
                        .with_document(principal_id);

                    batch.set(
                        ValueClass::Directory(DirectoryClass::Principal(principal_id)),
                        Archiver::new(principal)
                            .serialize()
                            .caused_by(trc::location!())?,
                    );
                    num_migrated += 1;

                    server
                        .store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }
                Err(_) => {
                    if let Err(err) = legacy.deserialize_untrusted::<Principal>() {
                        return Err(err.account_id(principal_id).caused_by(trc::location!()));
                    }
                }
            },
            Ok(None) => (),
            Err(err) => {
                return Err(err.account_id(principal_id).caused_by(trc::location!()));
            }
        }
    }

    if num_migrated > 0 {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {num_migrated} principals",)
        );
    }

    Ok(principal_ids)
}

pub(crate) async fn migrate_principal_v0_13(server: &Server, account_id: u32) -> trc::Result<()> {
    let start_time = Instant::now();
    let num_push = migrate_push_subscriptions_v013(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_sieve = migrate_sieve_v013(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_calendars = migrate_calendar_v013(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_events = migrate_calendar_events_v013(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_event_scheduling = migrate_calendar_scheduling_v013(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_books = migrate_addressbook_v013(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_contacts = migrate_contacts_v013(server, account_id)
        .await
        .caused_by(trc::location!())?;

    if num_sieve > 0
        || num_books > 0
        || num_contacts > 0
        || num_calendars > 0
        || num_events > 0
        || num_push > 0
        || num_event_scheduling > 0
    {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!(
                "Migrated accountId {account_id} with {num_sieve} sieve scripts, {num_push} push subscriptions, {num_calendars} calendars, {num_events} calendar events, {num_event_scheduling} event scheduling, {num_books} address books and {num_contacts} contacts"
            ),
            Elapsed = start_time.elapsed()
        );
    }

    Ok(())
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct PrincipalV2 {
    pub id: u32,
    pub typ: Type,
    pub name: String,
    pub description: Option<String>,
    pub secrets: Vec<String>,
    pub emails: Vec<String>,
    pub quota: Option<u64>,
    pub tenant: Option<u32>,
    pub data: Vec<PrincipalDataV2>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum PrincipalDataV2 {
    MemberOf(Vec<u32>),
    Roles(Vec<u32>),
    Lists(Vec<u32>),
    Permissions(Vec<PermissionGrantV2>),
    Picture(String),
    ExternalMembers(Vec<String>),
    Urls(Vec<String>),
    PrincipalQuota(Vec<PrincipalQuotaV2>),
    Locale(String),
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct PrincipalQuotaV2 {
    pub quota: u64,
    pub typ: Type,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrantV2 {
    pub permission: PermissionV2,
    pub grant: bool,
}

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    EnumMethods,
)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionV2 {
    // WARNING: add new ids at the end (TODO: use static ids)

    // Admin
    Impersonate,
    UnlimitedRequests,
    UnlimitedUploads,
    DeleteSystemFolders,
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
    SpamFilterClassify,

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
    // WARNING: add new ids at the end (TODO: use static ids)
}
