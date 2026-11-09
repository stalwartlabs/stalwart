/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    SCOPE_CALENDARS, SCOPE_CONTACTS, SCOPE_FILES, SCOPE_FULL, SCOPE_MAIL, SCOPE_OFFLINE_ACCESS,
    SCOPE_OPENID, SCOPE_SECURITY, SCOPE_SETTINGS,
};
use crate::auth::{Permissions, TokenScope};
use directory::backend::oidc::ExternalScopes;
use registry::{
    schema::enums::{OAuthScope, Permission},
    types::map::Map,
};
use std::ops::{BitAnd, BitOr, BitOrAssign};
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
)]
#[repr(transparent)]
pub struct OAuthScopes(u16);

const SCOPE_NAMES: [(OAuthScopes, &str); 9] = [
    (OAuthScopes::OPENID, SCOPE_OPENID),
    (OAuthScopes::OFFLINE_ACCESS, SCOPE_OFFLINE_ACCESS),
    (OAuthScopes::MAIL, SCOPE_MAIL),
    (OAuthScopes::CONTACTS, SCOPE_CONTACTS),
    (OAuthScopes::CALENDARS, SCOPE_CALENDARS),
    (OAuthScopes::FILES, SCOPE_FILES),
    (OAuthScopes::SECURITY, SCOPE_SECURITY),
    (OAuthScopes::SETTINGS, SCOPE_SETTINGS),
    (OAuthScopes::FULL, SCOPE_FULL),
];

const SCOPED_SHIFT: u32 = 2;
const SCOPED_COMBINATIONS: usize = 1 << 6;

impl OAuthScopes {
    pub const NONE: Self = Self(0);
    pub const OPENID: Self = Self(1 << 0);
    pub const OFFLINE_ACCESS: Self = Self(1 << 1);
    pub const MAIL: Self = Self(1 << 2);
    pub const CONTACTS: Self = Self(1 << 3);
    pub const CALENDARS: Self = Self(1 << 4);
    pub const FILES: Self = Self(1 << 5);
    pub const SECURITY: Self = Self(1 << 6);
    pub const SETTINGS: Self = Self(1 << 7);
    pub const FULL: Self = Self(1 << 8);
    pub const ALWAYS_ALLOWED: Self = Self(Self::OPENID.0 | Self::OFFLINE_ACCESS.0);
    pub const INTEROPERABLE: Self =
        Self(Self::MAIL.0 | Self::CONTACTS.0 | Self::CALENDARS.0 | Self::FILES.0);
    pub const STALWART: Self = Self(Self::SECURITY.0 | Self::SETTINGS.0 | Self::FULL.0);
    pub const GRANTABLE: Self = Self(Self::INTEROPERABLE.0 | Self::STALWART.0);
    pub const ALL: Self = Self(Self::ALWAYS_ALLOWED.0 | Self::GRANTABLE.0);
    pub const DAV: Self = Self(Self::CONTACTS.0 | Self::CALENDARS.0 | Self::FILES.0);
    pub const EXPIRED_CREDENTIAL: Self = Self(Self::SECURITY.0 | Self::FULL.0);
    const SCOPED: Self = Self(Self::INTEROPERABLE.0 | Self::SECURITY.0 | Self::SETTINGS.0);

    pub const fn from_bits(bits: u16) -> Self {
        Self(bits & Self::ALL.0)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_external(scopes: ExternalScopes) -> Self {
        Self(((scopes.bits() as u16) << SCOPED_SHIFT) & Self::GRANTABLE.0)
    }

    pub fn from_name(name: &str) -> Self {
        hashify::map!(
            name.as_bytes(),
            OAuthScopes,
            "openid" => OAuthScopes::OPENID,
            "offline_access" => OAuthScopes::OFFLINE_ACCESS,
            "urn:ietf:params:oauth:scope:mail" => OAuthScopes::MAIL,
            "urn:ietf:params:oauth:scope:contacts" => OAuthScopes::CONTACTS,
            "urn:ietf:params:oauth:scope:calendars" => OAuthScopes::CALENDARS,
            "urn:ietf:params:oauth:scope:files" => OAuthScopes::FILES,
            "urn:stalwart:oauth:scope:security" => OAuthScopes::SECURITY,
            "urn:stalwart:oauth:scope:settings" => OAuthScopes::SETTINGS,
            "urn:stalwart:oauth:scope:full" => OAuthScopes::FULL,
        )
        .copied()
        .unwrap_or_default()
    }

    pub fn parse(scope: &str) -> Self {
        scope
            .split_ascii_whitespace()
            .fold(Self::NONE, |scopes, name| scopes | Self::from_name(name))
    }

    pub fn from_registry<'x>(scopes: impl IntoIterator<Item = &'x OAuthScope>) -> Self {
        scopes
            .into_iter()
            .fold(Self::NONE, |acc, scope| acc | Self::from(*scope))
    }

    pub fn to_registry(self) -> Map<OAuthScope> {
        Map::new(
            [
                (Self::MAIL, OAuthScope::Mail),
                (Self::CONTACTS, OAuthScope::Contacts),
                (Self::CALENDARS, OAuthScope::Calendars),
                (Self::FILES, OAuthScope::Files),
                (Self::SECURITY, OAuthScope::Security),
                (Self::SETTINGS, OAuthScope::Settings),
                (Self::FULL, OAuthScope::Full),
            ]
            .into_iter()
            .filter(|(bit, _)| self.contains(*bit))
            .map(|(_, scope)| scope)
            .collect(),
        )
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn grantable(self) -> Self {
        Self(self.0 & Self::GRANTABLE.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn allows_expired_credential(self) -> bool {
        self.intersects(Self::EXPIRED_CREDENTIAL)
    }

    pub fn names(self) -> impl Iterator<Item = &'static str> {
        SCOPE_NAMES
            .into_iter()
            .filter(move |(bit, _)| self.contains(*bit))
            .map(|(_, name)| name)
    }

    pub fn to_wire(self) -> String {
        let mut out = String::with_capacity(256);
        for name in self.names() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(name);
        }
        out
    }

    const fn scoped_index(self) -> usize {
        ((self.0 & Self::SCOPED.0) >> SCOPED_SHIFT) as usize
    }
}

impl From<OAuthScope> for OAuthScopes {
    fn from(scope: OAuthScope) -> Self {
        match scope {
            OAuthScope::Mail => Self::MAIL,
            OAuthScope::Contacts => Self::CONTACTS,
            OAuthScope::Calendars => Self::CALENDARS,
            OAuthScope::Files => Self::FILES,
            OAuthScope::Security => Self::SECURITY,
            OAuthScope::Settings => Self::SETTINGS,
            OAuthScope::Full => Self::FULL,
        }
    }
}

impl BitOr for OAuthScopes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for OAuthScopes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for OAuthScopes {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

macro_rules! permission_scopes {
    ($($(#[$attr:meta])* $scopes:path => [$($permission:ident),+ $(,)?]),+ $(,)?) => {
        pub const fn permission_scopes(permission: Permission) -> OAuthScopes {
            match permission {
                $($(#[$attr])* $(Permission::$permission)|+ => $scopes,)+
                _ => OAuthScopes::NONE,
            }
        }

        static SCOPE_PERMISSIONS: [Permissions; SCOPED_COMBINATIONS] = {
            let mut table = [const { Permissions::new() }; SCOPED_COMBINATIONS];
            $(
                $(#[$attr])*
                {
                    $(insert_scoped(&mut table, Permission::$permission as usize, $scopes);)+
                }
            )+
            table
        };
    };
}

permission_scopes!(
    OAuthScopes::ALL => [
        Authenticate,
        AuthenticateWithAlias,
    ],
    OAuthScopes::MAIL => [
        EmailSend,
        EmailReceive,
        JmapMailboxGet,
        JmapMailboxChanges,
        JmapMailboxQuery,
        JmapMailboxQueryChanges,
        JmapMailboxCreate,
        JmapMailboxUpdate,
        JmapMailboxDestroy,
        JmapThreadGet,
        JmapThreadChanges,
        JmapEmailGet,
        JmapEmailChanges,
        JmapEmailQuery,
        JmapEmailQueryChanges,
        JmapEmailCreate,
        JmapEmailUpdate,
        JmapEmailDestroy,
        JmapEmailCopy,
        JmapEmailImport,
        JmapEmailParse,
        JmapSearchSnippetGet,
        JmapIdentityGet,
        JmapIdentityChanges,
        JmapIdentityCreate,
        JmapIdentityUpdate,
        JmapIdentityDestroy,
        JmapEmailSubmissionGet,
        JmapEmailSubmissionChanges,
        JmapEmailSubmissionQuery,
        JmapEmailSubmissionQueryChanges,
        JmapEmailSubmissionCreate,
        JmapEmailSubmissionUpdate,
        JmapEmailSubmissionDestroy,
        JmapVacationResponseGet,
        JmapVacationResponseCreate,
        JmapVacationResponseUpdate,
        JmapVacationResponseDestroy,
        JmapSieveScriptGet,
        JmapSieveScriptQuery,
        JmapSieveScriptValidate,
        JmapSieveScriptCreate,
        JmapSieveScriptUpdate,
        JmapSieveScriptDestroy,
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
        ImapMetadataGet,
        ImapMetadataSet,
        ImapMetadataPrivate,
        Pop3Authenticate,
        Pop3List,
        Pop3Uidl,
        Pop3Stat,
        Pop3Retr,
        Pop3Dele,
        SieveAuthenticate,
        SieveListScripts,
        SieveSetActive,
        SieveGetScript,
        SievePutScript,
        SieveDeleteScript,
        SieveRenameScript,
        SieveCheckScript,
        SieveHaveSpace,
        SysSpamTrainingSampleGet,
        SysSpamTrainingSampleCreate,
        SysSpamTrainingSampleDestroy,
        SysSpamTrainingSampleQuery,
    ],
    OAuthScopes::CALENDARS => [
        CalendarAlarmsSend,
        CalendarSchedulingSend,
        CalendarSchedulingReceive,
        JmapPrincipalGetAvailability,
        JmapCalendarGet,
        JmapCalendarChanges,
        JmapCalendarCreate,
        JmapCalendarUpdate,
        JmapCalendarDestroy,
        JmapCalendarEventGet,
        JmapCalendarEventChanges,
        JmapCalendarEventQuery,
        JmapCalendarEventQueryChanges,
        JmapCalendarEventCreate,
        JmapCalendarEventUpdate,
        JmapCalendarEventDestroy,
        JmapCalendarEventCopy,
        JmapCalendarEventParse,
        JmapCalendarEventNotificationGet,
        JmapCalendarEventNotificationChanges,
        JmapCalendarEventNotificationQuery,
        JmapCalendarEventNotificationQueryChanges,
        JmapCalendarEventNotificationCreate,
        JmapCalendarEventNotificationUpdate,
        JmapCalendarEventNotificationDestroy,
        JmapParticipantIdentityGet,
        JmapParticipantIdentityChanges,
        JmapParticipantIdentityCreate,
        JmapParticipantIdentityUpdate,
        JmapParticipantIdentityDestroy,
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
    ],
    OAuthScopes::INTEROPERABLE => [
        JmapPushSubscriptionGet,
        JmapPushSubscriptionCreate,
        JmapPushSubscriptionUpdate,
        JmapPushSubscriptionDestroy,
        JmapPrincipalGet,
        JmapPrincipalQuery,
        JmapPrincipalChanges,
        JmapPrincipalQueryChanges,
        JmapQuotaGet,
        JmapQuotaChanges,
        JmapQuotaQuery,
        JmapQuotaQueryChanges,
        JmapBlobGet,
        JmapBlobCopy,
        JmapBlobLookup,
        JmapBlobUpload,
        JmapShareNotificationGet,
        JmapShareNotificationChanges,
        JmapShareNotificationQuery,
        JmapShareNotificationQueryChanges,
        JmapShareNotificationCreate,
        JmapShareNotificationUpdate,
        JmapShareNotificationDestroy,
        JmapCoreEcho,
        JmapMetadataGet,
        JmapMetadataSet,
        JmapMetadataPrivate,
    ],
    OAuthScopes::CONTACTS => [
        JmapAddressBookGet,
        JmapAddressBookChanges,
        JmapAddressBookCreate,
        JmapAddressBookUpdate,
        JmapAddressBookDestroy,
        JmapContactCardGet,
        JmapContactCardChanges,
        JmapContactCardQuery,
        JmapContactCardQueryChanges,
        JmapContactCardCreate,
        JmapContactCardUpdate,
        JmapContactCardDestroy,
        JmapContactCardCopy,
        JmapContactCardParse,
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
    ],
    OAuthScopes::FILES => [
        JmapFileNodeGet,
        JmapFileNodeChanges,
        JmapFileNodeQuery,
        JmapFileNodeQueryChanges,
        JmapFileNodeCreate,
        JmapFileNodeUpdate,
        JmapFileNodeDestroy,
        JmapFileNodeCopy,
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
    ],
    OAuthScopes::DAV => [
        DavSyncCollection,
        DavExpandProperty,
        DavPrincipalAcl,
        DavPrincipalList,
        DavPrincipalMatch,
        DavPrincipalSearch,
        DavPrincipalSearchPropSet,
    ],
    OAuthScopes::SECURITY => [
        SysAccountPasswordGet,
        SysAccountPasswordUpdate,
        SysAppPasswordGet,
        SysAppPasswordCreate,
        SysAppPasswordUpdate,
        SysAppPasswordDestroy,
        SysAppPasswordQuery,
        SysApiKeyGet,
        SysApiKeyCreate,
        SysApiKeyUpdate,
        SysApiKeyDestroy,
        SysApiKeyQuery,
        SysPasskeyGet,
        SysPasskeyCreate,
        SysPasskeyUpdate,
        SysPasskeyDestroy,
        SysPasskeyQuery,
        SysOAuthGrantGet,
        SysOAuthGrantDestroy,
        SysOAuthGrantQuery,
    ],
    OAuthScopes::SETTINGS => [
        SysAccountSettingsGet,
        SysAccountSettingsUpdate,
        SysPublicKeyGet,
        SysPublicKeyCreate,
        SysPublicKeyUpdate,
        SysPublicKeyDestroy,
        SysPublicKeyQuery,
    ],
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    OAuthScopes::SETTINGS => [
        SysMaskedEmailGet,
        SysMaskedEmailCreate,
        SysMaskedEmailUpdate,
        SysMaskedEmailDestroy,
        SysMaskedEmailQuery,
    ],
    // SPDX-SnippetEnd
);

const fn insert_scoped(
    table: &mut [Permissions; SCOPED_COMBINATIONS],
    permission: usize,
    scopes: OAuthScopes,
) {
    let always = scopes.intersects(OAuthScopes::OPENID);
    let mut idx = 0;
    while idx < SCOPED_COMBINATIONS {
        if always || OAuthScopes((idx as u16) << SCOPED_SHIFT).intersects(scopes) {
            table[idx].insert(permission);
        }
        idx += 1;
    }
}

pub fn scope_permissions(scopes: OAuthScopes) -> &'static Permissions {
    &SCOPE_PERMISSIONS[scopes.scoped_index()]
}

impl TokenScope {
    #[inline]
    pub const fn grant_id(self) -> Option<u64> {
        match self {
            TokenScope::Grant { grant_id, .. } => Some(grant_id),
            TokenScope::External { .. } => None,
        }
    }

    #[inline]
    pub const fn restricted_scopes(self) -> Option<OAuthScopes> {
        match self {
            TokenScope::Grant { scopes, .. } | TokenScope::External { scopes }
                if scopes.contains(OAuthScopes::FULL) =>
            {
                None
            }
            TokenScope::Grant { scopes, .. } | TokenScope::External { scopes } => Some(scopes),
        }
    }

    #[inline]
    pub const fn allows_expired_credential(self) -> bool {
        match self {
            TokenScope::Grant { scopes, .. } => scopes.allows_expired_credential(),
            TokenScope::External { .. } => true,
        }
    }

    #[inline]
    pub fn permissions(self) -> Option<&'static Permissions> {
        self.restricted_scopes().map(scope_permissions)
    }
}

macro_rules! data_type_scopes {
    ($($scopes:expr => [$($data_type:ident),+ $(,)?]),+ $(,)?) => {
        pub const fn data_type_scopes(data_type: DataType) -> OAuthScopes {
            match data_type {
                $($(DataType::$data_type)|+ => $scopes,)+
                DataType::None => OAuthScopes::NONE,
            }
        }

        static SCOPE_DATA_TYPES: [u64; SCOPED_COMBINATIONS] = {
            let mut table = [0u64; SCOPED_COMBINATIONS];
            $($(insert_data_type(&mut table, DataType::$data_type as u64, $scopes);)+)+
            table
        };
    };
}

data_type_scopes!(
    OAuthScopes::MAIL => [
        Email,
        EmailDelivery,
        EmailSubmission,
        Mailbox,
        Thread,
        Identity,
        SearchSnippet,
        VacationResponse,
        Mdn,
        SieveScript,
    ],
    OAuthScopes::CALENDARS => [
        Calendar,
        CalendarEvent,
        CalendarEventNotification,
        ParticipantIdentity,
        CalendarAlert,
    ],
    OAuthScopes::CONTACTS => [AddressBook, ContactCard],
    OAuthScopes::FILES => [FileNode],
    OAuthScopes::INTEROPERABLE => [
        Core,
        PushSubscription,
        Quota,
        Principal,
        ShareNotification,
    ],
);

const fn insert_data_type(
    table: &mut [u64; SCOPED_COMBINATIONS],
    data_type: u64,
    scopes: OAuthScopes,
) {
    let mut idx = 0;
    while idx < SCOPED_COMBINATIONS {
        if OAuthScopes((idx as u16) << SCOPED_SHIFT).intersects(scopes) {
            table[idx] |= 1 << data_type;
        }
        idx += 1;
    }
}

pub fn scope_data_types(scopes: OAuthScopes) -> Bitmap<DataType> {
    Bitmap::from_bits(SCOPE_DATA_TYPES[scopes.scoped_index()])
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/scope/tests.rs"]
mod tests;
