/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{Permissions, PermissionsGroup},
};
use ahash::AHashSet;
use registry::schema::{enums::Permission, structs::PermissionsList};
use trc::AddContext;

impl Server {
    pub async fn add_role_permissions(
        &self,
        mut base_permissions: PermissionsGroup,
        roles: impl IntoIterator<Item = u32>,
    ) -> trc::Result<PermissionsGroup> {
        let mut role_ids = roles.into_iter().collect::<Vec<u32>>();
        let mut fetched_role_ids = AHashSet::new();

        while let Some(role_id) = role_ids.pop() {
            if fetched_role_ids.insert(role_id) {
                let role = self.role(role_id).await.caused_by(trc::location!())?;

                base_permissions.union(&role.permissions);
                role_ids.extend(role.id_roles.iter().copied());
            }
        }

        Ok(base_permissions)
    }
}

impl PermissionsGroup {
    pub fn with_merge(mut self, merge: bool) -> Self {
        self.merge = merge;
        self
    }

    pub fn union(&mut self, other: &PermissionsGroup) {
        self.enabled.union(&other.enabled);
        self.disabled.union(&other.disabled);
    }

    pub fn restrict(&mut self, other: &PermissionsGroup) {
        self.enabled.intersection(&other.enabled);
        self.disabled.union(&other.disabled);
    }

    pub fn finalize(mut self) -> Permissions {
        self.enabled.difference(&self.disabled);
        self.enabled
    }

    pub fn finalize_as_ref(&self) -> Permissions {
        let mut enabled = self.enabled.clone();
        enabled.difference(&self.disabled);
        enabled
    }

    pub fn user() -> Self {
        let mut permissions = PermissionsGroup::default();
        for permission in [
            Permission::Authenticate,
            Permission::AuthenticateOauth,
            Permission::EmailSend,
            Permission::EmailReceive,
            Permission::ManageEncryption,
            Permission::ManagePasswords,
            Permission::JmapEmailGet,
            Permission::JmapMailboxGet,
            Permission::JmapThreadGet,
            Permission::JmapIdentityGet,
            Permission::JmapEmailSubmissionGet,
            Permission::JmapPushSubscriptionGet,
            Permission::JmapSieveScriptGet,
            Permission::JmapVacationResponseGet,
            Permission::JmapQuotaGet,
            Permission::JmapBlobGet,
            Permission::JmapEmailSet,
            Permission::JmapMailboxSet,
            Permission::JmapIdentitySet,
            Permission::JmapEmailSubmissionSet,
            Permission::JmapPushSubscriptionSet,
            Permission::JmapSieveScriptSet,
            Permission::JmapVacationResponseSet,
            Permission::JmapEmailChanges,
            Permission::JmapMailboxChanges,
            Permission::JmapThreadChanges,
            Permission::JmapIdentityChanges,
            Permission::JmapEmailSubmissionChanges,
            Permission::JmapQuotaChanges,
            Permission::JmapEmailCopy,
            Permission::JmapBlobCopy,
            Permission::JmapEmailImport,
            Permission::JmapEmailParse,
            Permission::JmapEmailQueryChanges,
            Permission::JmapMailboxQueryChanges,
            Permission::JmapEmailSubmissionQueryChanges,
            Permission::JmapSieveScriptQueryChanges,
            Permission::JmapQuotaQueryChanges,
            Permission::JmapEmailQuery,
            Permission::JmapMailboxQuery,
            Permission::JmapEmailSubmissionQuery,
            Permission::JmapSieveScriptQuery,
            Permission::JmapQuotaQuery,
            Permission::JmapSearchSnippet,
            Permission::JmapSieveScriptValidate,
            Permission::JmapBlobLookup,
            Permission::JmapBlobUpload,
            Permission::JmapEcho,
            Permission::ImapAuthenticate,
            Permission::ImapAclGet,
            Permission::ImapAclSet,
            Permission::ImapMyRights,
            Permission::ImapListRights,
            Permission::ImapAppend,
            Permission::ImapCapability,
            Permission::ImapId,
            Permission::ImapCopy,
            Permission::ImapMove,
            Permission::ImapCreate,
            Permission::ImapDelete,
            Permission::ImapEnable,
            Permission::ImapExpunge,
            Permission::ImapFetch,
            Permission::ImapIdle,
            Permission::ImapList,
            Permission::ImapLsub,
            Permission::ImapNamespace,
            Permission::ImapRename,
            Permission::ImapSearch,
            Permission::ImapSort,
            Permission::ImapSelect,
            Permission::ImapExamine,
            Permission::ImapStatus,
            Permission::ImapStore,
            Permission::ImapSubscribe,
            Permission::ImapThread,
            Permission::Pop3Authenticate,
            Permission::Pop3List,
            Permission::Pop3Uidl,
            Permission::Pop3Stat,
            Permission::Pop3Retr,
            Permission::Pop3Dele,
            Permission::SieveAuthenticate,
            Permission::SieveListScripts,
            Permission::SieveSetActive,
            Permission::SieveGetScript,
            Permission::SievePutScript,
            Permission::SieveDeleteScript,
            Permission::SieveRenameScript,
            Permission::SieveCheckScript,
            Permission::SieveHaveSpace,
            Permission::DavSyncCollection,
            Permission::DavExpandProperty,
            Permission::DavPrincipalAcl,
            Permission::DavPrincipalList,
            Permission::DavPrincipalSearch,
            Permission::DavPrincipalMatch,
            Permission::DavPrincipalSearchPropSet,
            Permission::DavFilePropFind,
            Permission::DavFilePropPatch,
            Permission::DavFileGet,
            Permission::DavFileMkCol,
            Permission::DavFileDelete,
            Permission::DavFilePut,
            Permission::DavFileCopy,
            Permission::DavFileMove,
            Permission::DavFileLock,
            Permission::DavFileAcl,
            Permission::DavCardPropFind,
            Permission::DavCardPropPatch,
            Permission::DavCardGet,
            Permission::DavCardMkCol,
            Permission::DavCardDelete,
            Permission::DavCardPut,
            Permission::DavCardCopy,
            Permission::DavCardMove,
            Permission::DavCardLock,
            Permission::DavCardAcl,
            Permission::DavCardQuery,
            Permission::DavCardMultiGet,
            Permission::DavCalPropFind,
            Permission::DavCalPropPatch,
            Permission::DavCalGet,
            Permission::DavCalMkCol,
            Permission::DavCalDelete,
            Permission::DavCalPut,
            Permission::DavCalCopy,
            Permission::DavCalMove,
            Permission::DavCalLock,
            Permission::DavCalAcl,
            Permission::DavCalQuery,
            Permission::DavCalMultiGet,
            Permission::DavCalFreeBusyQuery,
            Permission::CalendarAlarms,
            Permission::CalendarSchedulingSend,
            Permission::CalendarSchedulingReceive,
            Permission::JmapAddressBookGet,
            Permission::JmapAddressBookSet,
            Permission::JmapAddressBookChanges,
            Permission::JmapContactCardGet,
            Permission::JmapContactCardChanges,
            Permission::JmapContactCardQuery,
            Permission::JmapContactCardQueryChanges,
            Permission::JmapContactCardSet,
            Permission::JmapContactCardCopy,
            Permission::JmapContactCardParse,
            Permission::JmapFileNodeGet,
            Permission::JmapFileNodeSet,
            Permission::JmapFileNodeChanges,
            Permission::JmapFileNodeQuery,
            Permission::JmapFileNodeQueryChanges,
            Permission::JmapPrincipalGetAvailability,
            Permission::JmapPrincipalChanges,
            Permission::JmapPrincipalQuery,
            Permission::JmapPrincipalGet,
            Permission::JmapPrincipalQueryChanges,
            Permission::JmapShareNotificationGet,
            Permission::JmapShareNotificationSet,
            Permission::JmapShareNotificationChanges,
            Permission::JmapShareNotificationQuery,
            Permission::JmapShareNotificationQueryChanges,
            Permission::JmapCalendarGet,
            Permission::JmapCalendarSet,
            Permission::JmapCalendarChanges,
            Permission::JmapCalendarEventGet,
            Permission::JmapCalendarEventSet,
            Permission::JmapCalendarEventChanges,
            Permission::JmapCalendarEventQuery,
            Permission::JmapCalendarEventQueryChanges,
            Permission::JmapCalendarEventCopy,
            Permission::JmapCalendarEventParse,
            Permission::JmapCalendarEventNotificationGet,
            Permission::JmapCalendarEventNotificationSet,
            Permission::JmapCalendarEventNotificationChanges,
            Permission::JmapCalendarEventNotificationQuery,
            Permission::JmapCalendarEventNotificationQueryChanges,
            Permission::JmapParticipantIdentityGet,
            Permission::JmapParticipantIdentitySet,
            Permission::JmapParticipantIdentityChanges,
        ] {
            permissions.enabled.set(permission as usize);
        }

        permissions
    }
}

impl From<PermissionsList> for PermissionsGroup {
    fn from(value: PermissionsList) -> Self {
        let mut permissions = PermissionsGroup::default();
        for (permission, is_set) in value.permissions {
            if is_set {
                permissions.enabled.set(permission as usize);
            } else {
                permissions.disabled.set(permission as usize);
            }
        }
        permissions
    }
}
